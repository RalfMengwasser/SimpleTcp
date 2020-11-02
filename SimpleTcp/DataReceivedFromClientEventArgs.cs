using System;
using System.Net;

namespace SimpleTcp
{
    /// <summary>
    /// Arguments for data received from client events.
    /// </summary>
    public class DataReceivedFromClientEventArgs : EventArgs
    {
        internal DataReceivedFromClientEventArgs(string ipPort, byte[] _Data, Protocol _Protocol, EndPoint _Endpoint)
        {
            IpPort = ipPort;
            Data = _Data;
            Protocol = _Protocol;
            Endpoint = _Endpoint;
        }

        /// <summary>
        /// The IP address and port number of the connected client socket.
        /// </summary>
        public string IpPort { get; }

        /// <summary>
        /// The data received from the client.
        /// </summary>
        public byte[] Data { get; set; }
        public WebSocketFrame WebSocketFrame { get; set; }
        public EndPoint Endpoint { get; set; }
        public IPAddress OriginalIP { get; set; }
        public int OriginalSrcPort { get; set; }
        public int OriginalDestPort { get; set; }
        public Protocol Protocol { get; set; }
    }
}