package grevcore 

type Packet struct {
	Header		string
	FileName	string 	// Leave Empty for ShellExec
	Data		[]byte
}

var (
	PacketNil	= Packet{"", "", nil}
)

const (
	AuthFail		= "GREVFAIL"
	FileReceiveHeader	= "GREVRCVF"
	AuthHeader		= "GREVAUTH"
	FileSendHeader		= "GREVSNDF"
	ShellExecHeader		= "GREVEXEC"
	HeaderSize		= 8
	FileNameHeaderSize	= 2
	MaxPacketSize		= 0xFFFF
)
