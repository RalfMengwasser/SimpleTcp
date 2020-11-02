using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace SimpleTcp
{
    /// <summary>
    /// SimpleTcp server with SSL support.  
    /// Set the ClientConnected, ClientDisconnected, and DataReceived events.  
    /// Once set, use Start() to begin listening for connections.
    /// </summary>
    public class SimpleTcpServer : IDisposable
    {
        #region Public-Members

        /// <summary>
        /// Indicates if the server is listening for connections.
        /// </summary>
        public bool IsListening
        {
            get
            {
                return _IsListening;
            }
        }

        /// <summary>
        /// SimpleTcp server settings.
        /// </summary>
        public SimpleTcpServerSettings Settings
        {
            get
            {
                return _Settings;
            }
            set
            {
                if (value == null) _Settings = new SimpleTcpServerSettings();
                else _Settings = value;
            }
        }

        /// <summary>
        /// SimpleTcp server events.
        /// </summary>
        public SimpleTcpServerEvents Events
        {
            get
            {
                return _Events;
            }
            set
            {
                if (value == null) _Events = new SimpleTcpServerEvents();
                else _Events = value;
            }
        }

        /// <summary>
        /// SimpleTcp statistics.
        /// </summary>
        public SimpleTcpStatistics Statistics
        {
            get
            {
                return _Statistics;
            }
        }

        /// <summary>
        /// SimpleTcp keepalive settings.
        /// </summary>
        public SimpleTcpKeepaliveSettings Keepalive
        {
            get
            {
                return _Keepalive;
            }
            set
            {
                if (value == null) _Keepalive = new SimpleTcpKeepaliveSettings();
                else _Keepalive = value;
            }
        }

        /// <summary>
        /// Method to invoke to send a log message.
        /// </summary>
        public Action<string, TCPLogType> Logger = null;

        #endregion

        #region Private-Members

        private string _Header = "[TCP] ";
        private SimpleTcpServerSettings _Settings = new SimpleTcpServerSettings();
        private SimpleTcpServerEvents _Events = new SimpleTcpServerEvents();
        private SimpleTcpKeepaliveSettings _Keepalive = new SimpleTcpKeepaliveSettings();
        private SimpleTcpStatistics _Statistics = new SimpleTcpStatistics();

        private string _ListenerIp;
        private IPAddress _IPAddress;
        private int _Port;
        private bool _Ssl;
        private string _PfxCertFilename;
        private string _PfxPassword;

        private X509Certificate2 _SslCertificate = null;
        private X509Certificate2Collection _SslCertificateCollection = null;

        private ConcurrentDictionary<string, ClientMetadata> _Clients = new ConcurrentDictionary<string, ClientMetadata>();
        private ConcurrentDictionary<string, DateTime> _ClientsLastSeen = new ConcurrentDictionary<string, DateTime>();
        private ConcurrentDictionary<string, DateTime> _ClientsKicked = new ConcurrentDictionary<string, DateTime>();
        private ConcurrentDictionary<string, DateTime> _ClientsTimedout = new ConcurrentDictionary<string, DateTime>();

        private TcpListener _Listener;
        private bool _IsListening = false;

        private CancellationTokenSource _TokenSource = new CancellationTokenSource();
        private CancellationToken _Token; 

        #endregion

        #region Constructors-and-Factories

        /// <summary>
        /// Instantiates the TCP server.  Set the ClientConnected, ClientDisconnected, and DataReceived callbacks.  Once set, use Start() to begin listening for connections.
        /// </summary>
        /// <param name="listenerIp">The listener IP address or hostname.</param>
        /// <param name="port">The TCP port on which to listen.</param>
        /// <param name="ssl">Enable or disable SSL.</param>
        /// <param name="pfxCertFilename">The filename of the PFX certificate file.</param>
        /// <param name="pfxPassword">The password to the PFX certificate file.</param>
        public SimpleTcpServer(string listenerIp, int port, bool ssl, string pfxCertFilename, string pfxPassword)
        {
            if (port < 0) throw new ArgumentException("Port must be zero or greater.");
             
            if (String.IsNullOrEmpty(listenerIp))
            {
                _IPAddress = IPAddress.Loopback;
                _ListenerIp = _IPAddress.ToString();
            }
            else if (listenerIp == "*" || listenerIp == "+")
            {
                _IPAddress = IPAddress.Any;
                _ListenerIp = listenerIp;
            }
            else
            {
                if (!IPAddress.TryParse(listenerIp, out _IPAddress))
                {
                    _IPAddress = Dns.GetHostEntry(listenerIp).AddressList[0];
                }

                _ListenerIp = listenerIp;
            }
              
            _Port = port;
            _Ssl = ssl;
            _PfxCertFilename = pfxCertFilename;
            _PfxPassword = pfxPassword;
            _IsListening = false;  
            _Token = _TokenSource.Token;
             
            if (_Ssl)
            {
                if (String.IsNullOrEmpty(pfxPassword))
                {
                    _SslCertificate = new X509Certificate2(pfxCertFilename);
                }
                else
                {
                    _SslCertificate = new X509Certificate2(pfxCertFilename, pfxPassword);
                }

                _SslCertificateCollection = new X509Certificate2Collection
                {
                    _SslCertificate
                };
            }

            Task.Run(() => MonitorForIdleClients(), _Token);
        }

        #endregion

        #region Public-Methods

        /// <summary>
        /// Dispose of the TCP server.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Start accepting connections.
        /// </summary>
        public void Start()
        {
            if (_IsListening) throw new InvalidOperationException("SimpleTcpServer is already running.");

            _Listener = new TcpListener(_IPAddress, _Port);

            if (_Keepalive.EnableTcpKeepAlives) EnableKeepalives();

            _Listener.Start(); 
            _TokenSource = new CancellationTokenSource();
            _Token = _TokenSource.Token;
            _Statistics = new SimpleTcpStatistics();
            Task.Run(() => AcceptConnections(), _Token); // sets _IsListening
        }

        /// <summary>
        /// Start accepting connections.
        /// </summary>
        /// <returns>Task.</returns>
        public Task StartAsync()
        {
            if (_IsListening) throw new InvalidOperationException("SimpleTcpServer is already running.");

            _Listener = new TcpListener(_IPAddress, _Port);

            if (_Keepalive.EnableTcpKeepAlives) EnableKeepalives();

            _Listener.Start();
            _TokenSource = new CancellationTokenSource();
            _Token = _TokenSource.Token;
            _Statistics = new SimpleTcpStatistics();
            return AcceptConnections(); // sets _IsListening
        }

        /// <summary>
        /// Stop accepting new connections.
        /// </summary>
        public void Stop()
        {
            if (!_IsListening) throw new InvalidOperationException("SimpleTcpServer is not running.");

            _IsListening = false;
            _Listener.Stop();
            _TokenSource.Cancel();

            Logger?.Invoke(_Header + "stopped", TCPLogType.Info);
        }

        /// <summary>
        /// Retrieve a list of client IP:port connected to the server.
        /// </summary>
        /// <returns>IEnumerable of strings, each containing client IP:port.</returns>
        public IEnumerable<string> GetClients()
        {
            List<string> clients = new List<string>(_Clients.Keys);
            return clients;
        }

        /// <summary>
        /// Determines if a client is connected by its IP:port.
        /// </summary>
        /// <param name="ipPort">The client IP:port string.</param>
        /// <returns>True if connected.</returns>
        public bool IsConnected(string ipPort)
        {
            if (String.IsNullOrEmpty(ipPort)) throw new ArgumentNullException(nameof(ipPort));

            ClientMetadata client = null;
            return (_Clients.TryGetValue(ipPort, out client));
        }

        /// <summary>
        /// Send data to the specified client by IP:port.
        /// </summary>
        /// <param name="ipPort">The client IP:port string.</param>
        /// <param name="data">String containing data to send.</param>
        public void Send(string ipPort, string data)
        {
            if (String.IsNullOrEmpty(ipPort)) throw new ArgumentNullException(nameof(ipPort));
            if (String.IsNullOrEmpty(data)) throw new ArgumentNullException(nameof(data));

            var c = GetSocket(ipPort);
            byte[] bytes = Encoding.UTF8.GetBytes(data);

            if (c != null && c.IsWebSocket)
            {
                bytes = EncodeWebSocketMessage(bytes);
            }

            MemoryStream ms = new MemoryStream();
            ms.Write(bytes, 0, bytes.Length);
            ms.Seek(0, SeekOrigin.Begin);
            SendInternal(ipPort, bytes.Length, ms);
        }

        /// <summary>
        /// Send data to the specified client by IP:port.
        /// </summary>
        /// <param name="ipPort">The client IP:port string.</param>
        /// <param name="data">Byte array containing data to send.</param>
        public void Send(string ipPort, byte[] data)
        {
            if (String.IsNullOrEmpty(ipPort)) throw new ArgumentNullException(nameof(ipPort));
            if (data == null || data.Length < 1) throw new ArgumentNullException(nameof(data));

            var c = GetSocket(ipPort);

            if (c != null && c.IsWebSocket)
            {
                data = EncodeWebSocketMessage(data);
            }

            MemoryStream ms = new MemoryStream();
            ms.Write(data, 0, data.Length);
            ms.Seek(0, SeekOrigin.Begin);
            SendInternal(ipPort, data.Length, ms);
        }

        /// <summary>
        /// Send data to the specified client by IP:port.
        /// </summary>
        /// <param name="ipPort">The client IP:port string.</param>
        /// <param name="contentLength">The number of bytes to read from the source stream to send.</param>
        /// <param name="stream">Stream containing the data to send.</param>
        public void Send(string ipPort, long contentLength, Stream stream)
        {
            if (String.IsNullOrEmpty(ipPort)) throw new ArgumentNullException(nameof(ipPort));
            if (contentLength < 1) return;
            if (stream == null) throw new ArgumentNullException(nameof(stream));
            if (!stream.CanRead) throw new InvalidOperationException("Cannot read from supplied stream.");
            SendInternal(ipPort, contentLength, stream);
        }

        /// <summary>
        /// Send data to the specified client by IP:port asynchronously.
        /// </summary>
        /// <param name="ipPort">The client IP:port string.</param>
        /// <param name="data">String containing data to send.</param>
        public async Task SendAsync(string ipPort, string data)
        {
            if (String.IsNullOrEmpty(ipPort)) throw new ArgumentNullException(nameof(ipPort));
            if (String.IsNullOrEmpty(data)) throw new ArgumentNullException(nameof(data));

            var c = GetSocket(ipPort);
            byte[] bytes = Encoding.UTF8.GetBytes(data);

            if (c != null && c.IsWebSocket)
            {
                bytes = EncodeWebSocketMessage(bytes);
            }

            MemoryStream ms = new MemoryStream();
            await ms.WriteAsync(bytes, 0, bytes.Length);
            ms.Seek(0, SeekOrigin.Begin);
            await SendInternalAsync(ipPort, bytes.Length, ms);
        }

        /// <summary>
        /// Send data to the specified client by IP:port asynchronously.
        /// </summary>
        /// <param name="ipPort">The client IP:port string.</param>
        /// <param name="data">Byte array containing data to send.</param>
        public async Task SendAsync(string ipPort, byte[] data)
        {
            if (String.IsNullOrEmpty(ipPort)) throw new ArgumentNullException(nameof(ipPort));
            if (data == null || data.Length < 1) throw new ArgumentNullException(nameof(data));

            var c = GetSocket(ipPort);

            if (c != null && c.IsWebSocket)
            {
                data = EncodeWebSocketMessage(data);
            }

            MemoryStream ms = new MemoryStream();
            await ms.WriteAsync(data, 0, data.Length);
            ms.Seek(0, SeekOrigin.Begin);
            await SendInternalAsync(ipPort, data.Length, ms);
        }

        /// <summary>
        /// Send data to the specified client by IP:port asynchronously.
        /// </summary>
        /// <param name="ipPort">The client IP:port string.</param>
        /// <param name="contentLength">The number of bytes to read from the source stream to send.</param>
        /// <param name="stream">Stream containing the data to send.</param>
        public async Task SendAsync(string ipPort, long contentLength, Stream stream)
        {
            if (String.IsNullOrEmpty(ipPort)) throw new ArgumentNullException(nameof(ipPort));
            if (contentLength < 1) return;
            if (stream == null) throw new ArgumentNullException(nameof(stream));
            if (!stream.CanRead) throw new InvalidOperationException("Cannot read from supplied stream.");
            await SendInternalAsync(ipPort, contentLength, stream);
        }

        /// <summary>
        /// Disconnects the specified client.
        /// </summary>
        /// <param name="ipPort">IP:port of the client.</param>
        public void DisconnectClient(string ipPort)
        {
            try
            {
                var c = GetSocket(ipPort);

                if (c != null)
                {
                    if (!_ClientsTimedout.ContainsKey(ipPort))
                    {
                        Logger?.Invoke(_Header + "kicking: " + ipPort, TCPLogType.Debug);
                        _ClientsKicked.TryAdd(ipPort, DateTime.Now);
                    }

                    _Clients.TryRemove(c.IpPort, out ClientMetadata destroyed);
                    c.Dispose();
                    Logger?.Invoke(_Header + "disposed: " + ipPort, TCPLogType.Debug);

                }
            }
            catch (Exception ex)
            {
                Logger?.Invoke(_Header + ex.Message, TCPLogType.Error);
            }
        }

        public void DowngradeFromWebSocket(string ipPort)
        {
            try
            {
                var c = GetSocket(ipPort);

                if (c != null)
                    c.IsWebSocket = false;
            }
            catch (Exception ex)
            {
                Logger?.Invoke(_Header + ex.Message, TCPLogType.Error);
            }
        }

        public bool CheckUpgradeToWebSocket(string ipPort, string Message)
        {
            try
            {
                var c = GetSocket(ipPort);

                if (c != null && !c.IsWebSocket)
                {
                    string NewMessageToUpper = Message.ToUpper();

                    if (NewMessageToUpper.Contains("UPGRADE: WEBSOCKET") && NewMessageToUpper.Contains("SEC-WEBSOCKET-KEY: "))
                    {
                        using (var crypto = System.Security.Cryptography.SHA1.Create())
                        {
                            string SecurityKeyReply = Convert.ToBase64String(crypto.ComputeHash(Encoding.UTF8.GetBytes(
                                   new System.Text.RegularExpressions.Regex("Sec-WebSocket-Key: ?(.*)", System.Text.RegularExpressions.RegexOptions.IgnoreCase).Match(Message).Groups[1].Value.Trim() + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")));

                            string data = "HTTP/1.1 101 Switching Protocols\r\n" +
                                          "Upgrade: websocket\r\n" +
                                          "Connection: Upgrade\r\n" +
                                          "Sec-WebSocket-Accept: " + SecurityKeyReply +
                                          //"Sec-WebSocket-Extensions: " + "\r\n" +
                                          "\r\n\r\n";

                            string ip = new System.Text.RegularExpressions.Regex("x-forwarded-for: ?(.*)", System.Text.RegularExpressions.RegexOptions.IgnoreCase).Match(Message).Groups[1].Value.Trim();
                            IPEndPoint e = (c.Client.Client.RemoteEndPoint as IPEndPoint);
                            string origip = e.Address.ToString();

                            if (!string.IsNullOrWhiteSpace(ip) && ip != origip)
                            {
                                c.IsProxied = true;
                                c.OriginalIP = IPAddress.Parse(ip);
                                c.OriginalDestPort = e.Port;
                            }

                            Send(ipPort, data);
                            c.IsWebSocket = true;

                            //Debug.WriteLine("\r\nWebSocket Request:\r\n\r\n" + Message + "WebSocket Handshake Reply:\r\n\r\n" + data);

                            return true;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Logger?.Invoke(_Header + ex.Message, TCPLogType.Error);
            }

            return false;
        }
        public bool IsWebSocket(string ipPort)
        {
            try
            {
                var c = GetSocket(ipPort);

                if (c != null)
                    return c.IsWebSocket;
            }
            catch (Exception ex)
            {
                Logger?.Invoke(_Header + ex.Message, TCPLogType.Error);
            }

            return false;
        }
        public Protocol GetClientProtocol(string ipPort)
        {
            try
            {
                var c = GetSocket(ipPort);

                if (c != null)
                    return c.IncomingProtocol;
            }
            catch (Exception ex)
            {
                Logger?.Invoke(_Header + ex.Message, TCPLogType.Error);
            }

            return Protocol.Unknown;
        }
        public void SetClientProtocol(string ipPort, Protocol NewProtocol)
        {
            try
            {
                var c = GetSocket(ipPort);

                if (c != null)
                    c.IncomingProtocol = NewProtocol;
            }
            catch (Exception ex)
            {
                Logger?.Invoke(_Header + ex.Message, TCPLogType.Error);
            }
        }

        #endregion

        #region Private-Methods

        private static WebSocketFrame DecodeWebSocketMessage(byte[] message)
        {
            WebSocketFrame frame = new WebSocketFrame();

            int FrameLength = 0;
            int DecodePasswordIndex = 0;

            frame.FinFlag = (message[0] & 128) != 0;
            frame.RSV1Flag = (message[0] & 64) != 0;
            frame.RSV2Flag = (message[0] & 32) != 0;
            frame.RSV3Flag = (message[0] & 16) != 0;
            frame.OpCode = (message[0] & 0xF);
            frame.Masked = (message[1] & 128) != 0;
            frame.Length = (message[1] - 128);

            // If not masked, messages are invalid and normally should disconnect
            if (!frame.Masked)
            {
                return null;
            }

            if (frame.Length <= 125)
            {
                DecodePasswordIndex = 2;
                FrameLength = frame.Length + 6;
            }
            else if (frame.Length == 126)
            {
                frame.Length = BitConverter.ToInt16(new byte[] { message[3], message[2] }, 0);
                DecodePasswordIndex = 4;
                FrameLength = frame.Length + 8;
            }
            else if (frame.Length == 127)
            {
                frame.Length = (int)BitConverter.ToInt64(new byte[] { message[9], message[8], message[7], message[6], message[5], message[4], message[3], message[2] }, 0);
                DecodePasswordIndex = 10;
                FrameLength = frame.Length + 14;
            }

            if (message.Length < FrameLength)
                return null;

            byte[] DecodePassword = new byte[] { message[DecodePasswordIndex], message[DecodePasswordIndex + 1], message[DecodePasswordIndex + 2], message[DecodePasswordIndex + 3] };

            int count = 0;
            for (int i = DecodePasswordIndex + 4; i < FrameLength; i++)
            {
                message[i] = (byte)(message[i] ^ DecodePassword[count % 4]);
                count++;
            }

            frame.Message = ASCIIEncoding.UTF8.GetString(message, DecodePasswordIndex + 4, frame.Length) + "\r\n";

            return frame;
        }
        private static byte[] EncodeWebSocketMessage(byte[] message)
        {
            int FrameLength;
            int DecodePasswordIndex;
            byte[] res;

            if (message.Length <= 125)
            {
                DecodePasswordIndex = 2;
                FrameLength = message.Length + 2;
                res = new byte[FrameLength];

                res[0] = 129;
                res[1] = (byte)message.Length;
            }
            else if (message.Length <= 65535)
            {
                DecodePasswordIndex = 4;
                FrameLength = message.Length + 4;
                res = new byte[FrameLength];

                res[0] = 129;
                res[1] = (byte)126;
                res[2] = (byte)((message.Length & 0xFF00) >> 8);
                res[3] = (byte)(message.Length & 0xFF);
            }
            else
            {
                DecodePasswordIndex = 10;
                FrameLength = message.Length + 10;
                res = new byte[FrameLength];

                res[0] = 129;
                res[1] = (byte)127;
                res[2] = 0;
                res[3] = 0;
                res[4] = 0;
                res[5] = 0;
                res[6] = (byte)((message.Length & 0xFF000000) >> 24);
                res[7] = (byte)((message.Length & 0xFF0000) >> 16);
                res[8] = (byte)((message.Length & 0xFF00) >> 8);
                res[9] = (byte)(message.Length & 0xFF);
            }

            int count = 0;
            for (int i = DecodePasswordIndex; i < FrameLength; i++)
            {
                res[i] = (byte)message[count];
                count++;
            }

            return res;
        }

        private ClientMetadata GetSocket(string ipPort)
        {
            if (!_Clients.TryGetValue(ipPort, out ClientMetadata client))
            {
                Logger?.Invoke(_Header + "unable to find client: " + ipPort, TCPLogType.Warn);
                return null;
            }
            else
            {
                return client;
            }
        }

        /// <summary>
        /// Dispose of the TCP server.
        /// </summary>
        /// <param name="disposing">Dispose of resources.</param>
        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                try
                {
                    if (_Clients != null && _Clients.Count > 0)
                    {
                        foreach (KeyValuePair<string, ClientMetadata> curr in _Clients)
                        {
                            curr.Value.Dispose();
                            Logger?.Invoke(_Header + "disconnected client: " + curr.Key, TCPLogType.Debug);
                        } 
                    }

                    _TokenSource.Cancel();
                    _TokenSource.Dispose();

                    if (_Listener != null && _Listener.Server != null)
                    {
                        _Listener.Server.Close();
                        _Listener.Server.Dispose();
                    }

                    if (_Listener != null)
                    {
                        _Listener.Stop();
                    }
                }
                catch (Exception e)
                {
                    Logger?.Invoke(_Header + "dispose exception:" +
                        Environment.NewLine +
                        e.ToString() +
                        Environment.NewLine, TCPLogType.Error);
                }

                _IsListening = false;

                Logger?.Invoke(_Header + "disposed", TCPLogType.Debug);
            }
        }
         
        private bool IsClientConnected(System.Net.Sockets.TcpClient client)
        {
            if (client.Connected)
            {
                if ((client.Client.Poll(0, SelectMode.SelectWrite)) && (!client.Client.Poll(0, SelectMode.SelectError)))
                {
                    byte[] buffer = new byte[1];
                    if (client.Client.Receive(buffer, SocketFlags.Peek) == 0)
                    {
                        return false;
                    }
                    else
                    {
                        return true;
                    }
                }
                else
                {
                    return false;
                }
            }
            else
            {
                return false;
            } 
        }

        private async Task AcceptConnections()
        {
            _IsListening = true;

            while (!_Token.IsCancellationRequested)
            {
                ClientMetadata client = null;

                try
                {
                    System.Net.Sockets.TcpClient tcpClient = await _Listener.AcceptTcpClientAsync(); 
                    string clientIp = tcpClient.Client.RemoteEndPoint.ToString();

                    client = new ClientMetadata(tcpClient);

                    if (_Ssl)
                    {
                        if (_Settings.AcceptInvalidCertificates)
                        { 
                            client.SslStream = new SslStream(client.NetworkStream, false, new RemoteCertificateValidationCallback(AcceptCertificate));
                        }
                        else
                        { 
                            client.SslStream = new SslStream(client.NetworkStream, false);
                        }

                        bool success = await StartTls(client);
                        if (!success)
                        {
                            client.Dispose();
                            continue;
                        }
                    }

                    _Clients.TryAdd(clientIp, client); 
                    _ClientsLastSeen.TryAdd(clientIp, DateTime.Now); 
                    Logger?.Invoke(_Header + "starting data receiver for: " + clientIp, TCPLogType.Debug); 
                    _Events.HandleClientConnected(this, new ClientConnectedEventArgs(clientIp)); 
                    Task unawaited = Task.Run(() => DataReceiver(client), _Token);
                }
                catch (OperationCanceledException)
                {
                    _IsListening = false;
                    if (client != null) client.Dispose();
                    return;
                }
                catch (ObjectDisposedException)
                {
                    if (client != null) client.Dispose();
                    continue;
                }
                catch (Exception e)
                {
                    if (client != null) client.Dispose();
                    Logger?.Invoke(_Header + "exception while awaiting connections: " + e.ToString(), TCPLogType.Error);
                    continue;
                } 
            }

            _IsListening = false;
        }

        private async Task<bool> StartTls(ClientMetadata client)
        {
            try
            { 
                await client.SslStream.AuthenticateAsServerAsync(
                    _SslCertificate,
                    _Settings.MutuallyAuthenticate, 
                    SslProtocols.Tls12, 
                    !_Settings.AcceptInvalidCertificates);

                if (!client.SslStream.IsEncrypted)
                {
                    Logger?.Invoke(_Header + "client " + client.IpPort + " not encrypted, disconnecting", TCPLogType.Debug);
                    client.Dispose();
                    return false;
                }

                if (!client.SslStream.IsAuthenticated)
                {
                    Logger?.Invoke(_Header + "client " + client.IpPort + " not SSL/TLS authenticated, disconnecting", TCPLogType.Debug);
                    client.Dispose();
                    return false;
                }

                if (_Settings.MutuallyAuthenticate && !client.SslStream.IsMutuallyAuthenticated)
                {
                    Logger?.Invoke(_Header + "client " + client.IpPort + " failed mutual authentication, disconnecting", TCPLogType.Debug);
                    client.Dispose();
                    return false;
                }
            }
            catch (Exception e)
            {
                Logger?.Invoke(_Header + "client " + client.IpPort + " SSL/TLS exception: " + Environment.NewLine + e.ToString(), TCPLogType.Error);
                client.Dispose();
                return false;
            }

            return true;
        }

        private bool AcceptCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            // return true; // Allow untrusted certificates.
            return _Settings.AcceptInvalidCertificates;
        }

        private async Task DataReceiver(ClientMetadata client)
        {
            Logger?.Invoke(_Header + "data receiver started for client " + client.IpPort, TCPLogType.Debug);
            
            while (true)
            {
                try
                { 
                    if (client.Token.IsCancellationRequested 
                        || !IsClientConnected(client.Client))
                    {
                        Logger?.Invoke(_Header + "client " + client.IpPort + " disconnected", TCPLogType.Debug);
                        break;
                    }

                    if (client.Token.IsCancellationRequested)
                    {
                        Logger?.Invoke(_Header + "cancellation requested (data receiver for client " + client.IpPort + ")", TCPLogType.Debug);
                        break;
                    } 

                    byte[] m_Buffer = await DataReadAsync(client);
                    if (m_Buffer == null)
                    { 
                        await Task.Delay(30);
                        continue;
                    }

                    int BufferStart = 0;
                    int nBytesRec = m_Buffer.Length;

                    // We support the PROXY protocol (currently v1)
                    // PROXY TCP4 192.168.0.37 192.168.0.121 57307 16248\r\n
                    // PROXY TCP6 ffff:f...f:ffff ffff:f...f:ffff 65535 65535\r\n
                    // \x0D \x0A \x0D \x0A \x00 \x0D \x0A \x51 \x55 \x49 \x54 \x0A
                    // Min 32 bytes, max 108 bytes
                    if (nBytesRec > 32 && m_Buffer[0] == 'P' && m_Buffer[1] == 'R' && m_Buffer[2] == 'O' && m_Buffer[3] == 'X' && m_Buffer[4] == 'Y' && m_Buffer[5] == ' ')
                    {
                        try
                        {
                            string msg = Encoding.UTF8.GetString(m_Buffer, 0, Math.Min(108, nBytesRec)); // 108 is the max we need to parse
                            string[] proxy = msg.Split(new string[] { "\r\n" }, StringSplitOptions.RemoveEmptyEntries);
                            string[] proxyparts = proxy[0].Split(new string[] { " " }, StringSplitOptions.RemoveEmptyEntries);

                            client.OriginalIP = IPAddress.Parse(proxyparts[2]);
                            client.OriginalSrcPort = int.Parse(proxyparts[4]);
                            client.OriginalDestPort = int.Parse(proxyparts[5]);

                            client.IsProxied = true;

                            int split = msg.IndexOf("\r\n");

                            if (split > 32)
                            {
                                nBytesRec -= split + 2;
                                BufferStart = split + 2;
                            }
                        }
                        catch (Exception)
                        {
                        }
                    }

                    byte[] package = new byte[nBytesRec];
                    Buffer.BlockCopy(m_Buffer, BufferStart, package, 0, nBytesRec);

                    var args = new DataReceivedFromClientEventArgs(client.IpPort, package, client.IncomingProtocol, client.Client.Client.RemoteEndPoint);
                    args.Data = package;
                    args.Protocol = client.IncomingProtocol;

                    if (client.IsWebSocket)
                    {
                        args.WebSocketFrame = DecodeWebSocketMessage(package);

                        if (args.WebSocketFrame.OpCode == 0x9)
                        {
                            package[0] = (byte)((package[0] & 0xF0) + 0xA);
                            Send(client.IpPort, package);

                            return;
                        }
                    }

                    if (client.IsProxied)
                    {
                        args.OriginalIP = client.OriginalIP;
                        args.OriginalSrcPort = client.OriginalSrcPort;
                        args.OriginalDestPort = client.OriginalDestPort;
                    }

                    _Events.HandleDataReceived(this, args);
                    _Statistics.ReceivedBytes += package.Length;
                    UpdateClientLastSeen(client.IpPort);
                }
                catch (SocketException)
                {
                    Logger?.Invoke(_Header + "data receiver socket exception (disconnection) for " + client.IpPort, TCPLogType.Debug);
                }
                catch (Exception e)
                {
                    Logger?.Invoke(_Header + "data receiver exception for client " + client.IpPort + ":" +
                        Environment.NewLine +
                        e.ToString() +
                        Environment.NewLine, TCPLogType.Warn);

                    break;
                }
            }

            Logger?.Invoke(_Header + "data receiver terminated for client " + client.IpPort, TCPLogType.Debug);

            if (_ClientsKicked.ContainsKey(client.IpPort))
            {
                _Events.HandleClientDisconnected(this, new ClientDisconnectedEventArgs(client.IpPort, DisconnectReason.Kicked));
            }
            else if (_ClientsTimedout.ContainsKey(client.IpPort))
            {
                _Events.HandleClientDisconnected(this, new ClientDisconnectedEventArgs(client.IpPort, DisconnectReason.Timeout));
            }
            else
            {
                _Events.HandleClientDisconnected(this, new ClientDisconnectedEventArgs(client.IpPort, DisconnectReason.Normal));
            }

            DateTime removedTs;
            _Clients.TryRemove(client.IpPort, out ClientMetadata destroyed);
            _ClientsLastSeen.TryRemove(client.IpPort, out removedTs);
            _ClientsKicked.TryRemove(client.IpPort, out removedTs);
            _ClientsTimedout.TryRemove(client.IpPort, out removedTs); 
            client.Dispose();
        }
           
        private async Task<byte[]> DataReadAsync(ClientMetadata client)
        { 
            if (client.Token.IsCancellationRequested) throw new OperationCanceledException();
            if (!client.NetworkStream.CanRead) return null;
            if (!client.NetworkStream.DataAvailable) return null;
            if (_Ssl && !client.SslStream.CanRead) return null;

            byte[] buffer = new byte[_Settings.StreamBufferSize];
            int read = 0;

            if (!_Ssl)
            {
                using (MemoryStream ms = new MemoryStream())
                {
                    while (true)
                    {
                        read = await client.NetworkStream.ReadAsync(buffer, 0, buffer.Length);

                        if (read > 0)
                        {
                            ms.Write(buffer, 0, read);
                            return ms.ToArray();
                        }
                        else
                        {
                            throw new SocketException();
                        }
                    }
                }
            }
            else
            {
                using (MemoryStream ms = new MemoryStream())
                {
                    while (true)
                    {
                        read = await client.SslStream.ReadAsync(buffer, 0, buffer.Length);

                        if (read > 0)
                        {
                            ms.Write(buffer, 0, read);
                            return ms.ToArray();
                        }
                        else
                        {
                            throw new SocketException();
                        }
                    }
                }
            } 
        }

        private async Task MonitorForIdleClients()
        {
            while (!_Token.IsCancellationRequested)
            { 
                await Task.Delay(_Settings.IdleClientEvaluationIntervalSeconds, _Token);

                if (_Settings.IdleClientTimeoutSeconds == 0) continue;

                try
                { 
                    DateTime idleTimestamp = DateTime.Now.AddSeconds(-1 * _Settings.IdleClientTimeoutSeconds);

                    foreach (KeyValuePair<string, DateTime> curr in _ClientsLastSeen)
                    { 
                        if (curr.Value < idleTimestamp)
                        {
                            _ClientsTimedout.TryAdd(curr.Key, DateTime.Now);
                            Logger?.Invoke(_Header + "disconnecting " + curr.Key + " due to timeout", TCPLogType.Debug);
                            DisconnectClient(curr.Key);
                        }
                    }
                }
                catch (Exception e)
                {
                    Logger?.Invoke(_Header + "monitor exception: " + e.ToString(), TCPLogType.Error);
                }
            }
        }
         
        private void UpdateClientLastSeen(string ipPort)
        {
            if (_ClientsLastSeen.ContainsKey(ipPort))
            {
                DateTime ts;
                _ClientsLastSeen.TryRemove(ipPort, out ts);
            }
             
            _ClientsLastSeen.TryAdd(ipPort, DateTime.Now);
        }

        private void SendInternal(string ipPort, long contentLength, Stream stream)
        {
            ClientMetadata client = null;
            if (!_Clients.TryGetValue(ipPort, out client)) return;
            if (client == null) return;

            long bytesRemaining = contentLength;
            int bytesRead = 0;
            byte[] buffer = new byte[_Settings.StreamBufferSize];

            try
            {
                client.SendLock.Wait();

                while (bytesRemaining > 0)
                {
                    bytesRead = stream.Read(buffer, 0, buffer.Length);
                    if (bytesRead > 0)
                    {
                        if (!_Ssl) client.NetworkStream.Write(buffer, 0, bytesRead); 
                        else client.SslStream.Write(buffer, 0, bytesRead); 

                        bytesRemaining -= bytesRead;
                        _Statistics.SentBytes += bytesRead;
                    }
                }

                if (!_Ssl) client.NetworkStream.Flush();
                else client.SslStream.Flush();
            }
            finally
            {
                if (client != null) client.SendLock.Release();
            }
        }

        private async Task SendInternalAsync(string ipPort, long contentLength, Stream stream)
        {
            ClientMetadata client = null;
            if (!_Clients.TryGetValue(ipPort, out client)) return;
            if (client == null) return;

            long bytesRemaining = contentLength;
            int bytesRead = 0;
            byte[] buffer = new byte[_Settings.StreamBufferSize];

            try
            {
                await client.SendLock.WaitAsync();

                while (bytesRemaining > 0)
                {
                    bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length);
                    if (bytesRead > 0)
                    {
                        if (!_Ssl) await client.NetworkStream.WriteAsync(buffer, 0, bytesRead);
                        else await client.SslStream.WriteAsync(buffer, 0, bytesRead);

                        bytesRemaining -= bytesRead;
                        _Statistics.SentBytes += bytesRead;
                    }
                }

                if (!_Ssl) await client.NetworkStream.FlushAsync();
                else await client.SslStream.FlushAsync();
            }
            finally
            {
                if (client != null) client.SendLock.Release();
            }
        }

        private void EnableKeepalives()
        {
            try
            {
#if NETCOREAPP

                _Listener.Server.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.KeepAlive, true);
                _Listener.Server.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveTime, _Keepalive.TcpKeepAliveTime);
                _Listener.Server.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveInterval, _Keepalive.TcpKeepAliveInterval);
                _Listener.Server.SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.TcpKeepAliveRetryCount, _Keepalive.TcpKeepAliveRetryCount);

#elif NETFRAMEWORK

            byte[] keepAlive = new byte[12];

            // Turn keepalive on
            Buffer.BlockCopy(BitConverter.GetBytes((uint)1), 0, keepAlive, 0, 4);

            // Set TCP keepalive time
            Buffer.BlockCopy(BitConverter.GetBytes((uint)_Keepalive.TcpKeepAliveTime), 0, keepAlive, 4, 4); 

            // Set TCP keepalive interval
            Buffer.BlockCopy(BitConverter.GetBytes((uint)_Keepalive.TcpKeepAliveInterval), 0, keepAlive, 8, 4); 

            // Set keepalive settings on the underlying Socket
            _Listener.Server.IOControl(IOControlCode.KeepAliveValues, keepAlive, null);

#elif NETSTANDARD

#endif
            }
            catch (Exception)
            {
                Logger?.Invoke(_Header + "keepalives not supported on this platform, disabled", TCPLogType.Warn);
            }
        }

        #endregion
    }
}
