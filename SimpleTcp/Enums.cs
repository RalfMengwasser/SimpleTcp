
namespace SimpleTcp
{
    public enum Protocol
    {
        Unknown,
        TCP,
        HTTP,
        HTTPS,
        WebSocket,
        MQTT,
        FTP,
        SFTP,
        DNS,
        SQL,
        SMTP,
        SMTPS,
        POP3,
        IMAP,
        SSH,
        Telnet,
        RDP,
        VNC,
        NTP,
        DHCP,
        Custom1,
        Custom2,
        Custom3,
        Custom4,
        Custom5,
        Custom6,
        Custom7,
        Custom8,
        Custom9,
    }

    public enum TCPLogType
    {
        Debug,
        Info,
        Success,
        Warn,
        Error,
        Fatal
    }
}
