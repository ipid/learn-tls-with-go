package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
)

var CONTENT_TYPE_TABLE = map[byte]string{
	0:  "Invalid",
	20: "Change Cipher Spec",
	21: "Alert",
	22: "Handshake",
	23: "Application Data",
}

var HANDSHAKE_TYPE_TABLE = map[byte]string{
	0:   "Hello Request",
	1:   "Client Hello",
	2:   "Server Hello",
	4:   "New Session Ticket",
	5:   "End Of Early Data",
	8:   "Encrypted Extensions",
	11:  "Certificate",
	12:  "Server Key Exchange",
	13:  "Certificate Request",
	14:  "Server Hello Done",
	15:  "Certificate Verify",
	16:  "Client Key Exchange",
	20:  "Finished",
	24:  "Key Update",
	254: "Message Hash",
}

var ALERT_LEVEL_TABLE = map[byte]string{
	1: "Warning",
	2: "Fatal",
}

var ALERT_DESCRIPTION_TABLE = map[byte]string{
	0:   "Close Notify",
	10:  "Unexpected Message",
	20:  "Bad Record MAC",
	22:  "Record Overflow",
	30:  "Decompression Failure",
	40:  "Handshake Failure",
	41:  "No Certificate",
	42:  "Bad Certificate",
	43:  "Unsupported Certificate",
	44:  "Certificate Revoked",
	45:  "Certificate Expired",
	46:  "Certificate Unknown",
	47:  "Illegal Parameter",
	48:  "Unknown CA",
	49:  "Access Denied",
	50:  "Decode Error",
	51:  "Decrypt Error",
	60:  "Export Restriction",
	70:  "Protocol Version",
	71:  "Insufficient Security",
	80:  "Internal Error",
	86:  "Inappropriate Fallback",
	90:  "User Canceled",
	100: "No Renegotiation",
	109: "Missing Extension",
	110: "Unsupported Extension",
	112: "Unrecognized Name",
	113: "Bad Certificate Status Response",
	115: "Unknown PSK Identity",
	116: "Certificate Required",
	120: "No Application Protocol",
}

func panicIfErr(err error, funcName string) {
	if err != nil {
		panic(fmt.Sprintf("[%s] 错误: %v", funcName, err))
	}
}

func copyDataFromConnToConn(from, to *net.TCPConn) {
	recordLayerHeader := make([]byte, 5)
	buf := make([]byte, 16384+5)

	for {
		_, err := io.ReadFull(from, recordLayerHeader)
		if err != nil {
			break
		}

		// 读取 record layer 的长度
		currentRecordLength := binary.BigEndian.Uint16(recordLayerHeader[3:5])
		if currentRecordLength > 16384 {
			// RFC 8446 5.1 规定 record layer 的长度最大为 16384
			break
		}

		_, err = io.ReadFull(from, buf[:currentRecordLength])
		if err != nil {
			break
		}

		_, err = to.Write(recordLayerHeader)
		_, err1 := to.Write(buf[:currentRecordLength])

		if err != nil || err1 != nil {
			break
		}

		version := binary.BigEndian.Uint16(recordLayerHeader[1:3])
		contentType, hasType := CONTENT_TYPE_TABLE[recordLayerHeader[0]]
		if !hasType {
			contentType = "未知"
		}

		extraInfo := ""
		if contentType == "Handshake" {
			handshakeType, hasType := HANDSHAKE_TYPE_TABLE[buf[0]]
			if !hasType {
				handshakeType = "未知"
			}
			handshakeLength := uint32(buf[1])<<16 | uint32(buf[2])<<8 | uint32(buf[3])
			extraInfo = fmt.Sprintf("，握手类型：%s (%d)，握手长度：%d", handshakeType, buf[0], handshakeLength)
		} else if contentType == "Alert" {
			alertLevel, hasType := ALERT_LEVEL_TABLE[buf[0]]
			if !hasType {
				alertLevel = "未知"
			}
			alertDescription, hasType := ALERT_DESCRIPTION_TABLE[buf[1]]
			if !hasType {
				alertDescription = "未知"
			}
			extraInfo = fmt.Sprintf("，警报级别：%s (%d)，警报描述：%s (%d)", alertLevel, buf[0], alertDescription, buf[1])
		}

		fmt.Printf(
			"[copyDataFromConnToConn %s --> %s] 转发了记录层数据，内容类型：%s (%d)，版本：0x%04X，长度：%d%s\n",
			from.RemoteAddr(),
			to.RemoteAddr(),
			contentType,
			recordLayerHeader[0],
			version,
			currentRecordLength,
			extraInfo,
		)
	}

	_ = from.CloseRead()
	_ = to.CloseWrite()
	fmt.Printf(
		"[copyDataFromConnToConn %s --> %s] 连接已关闭\n",
		from.RemoteAddr(),
		to.RemoteAddr(),
	)
}

func handleNewIncomingConn(inConn *net.TCPConn, remoteAddr *net.TCPAddr) {
	outConn, err := net.DialTCP("tcp4", nil, remoteAddr)
	if err != nil {
		_ = inConn.Close()
		return
	}

	go copyDataFromConnToConn(inConn, outConn)
	go copyDataFromConnToConn(outConn, inConn)
}

func main() {
	var argRemoteAddr, argLocalAddr string

	flag.StringVar(&argRemoteAddr, "r", "", "远程地址")
	flag.StringVar(&argLocalAddr, "l", "", "本地地址")
	flag.Parse()

	if argRemoteAddr == "" || argLocalAddr == "" {
		panic("请填写必要的参数 -l 和 -r")
	}

	tcpRemoteAddr, err := net.ResolveTCPAddr("tcp4", argRemoteAddr)
	panicIfErr(err, "main")

	tcpLocalAddr, err := net.ResolveTCPAddr("tcp4", argLocalAddr)
	panicIfErr(err, "main")

	listener, err := net.ListenTCP("tcp4", tcpLocalAddr)
	panicIfErr(err, "main")

	fmt.Printf("正在监听 %s……\n", tcpLocalAddr)

	for {
		inConn, err := listener.AcceptTCP()
		panicIfErr(err, "main")

		go handleNewIncomingConn(inConn, tcpRemoteAddr)
	}
}
