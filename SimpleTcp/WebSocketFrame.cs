using System;
using System.Collections.Generic;
using System.Text;

namespace SimpleTcp
{
    public class WebSocketFrame
    {
        public bool FinFlag;
        public bool RSV1Flag;
        public bool RSV2Flag;
        public bool RSV3Flag;
        public int OpCode;
        public bool Masked;
        public int Length;
        public string Message;
    }
}
