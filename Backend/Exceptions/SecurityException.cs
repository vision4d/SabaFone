using System;

namespace SabaFone.Backend.Exceptions
{
    public class SecurityException : Exception
    {
        public SecurityException() { }
        public SecurityException(string message) : base(message) { }
        public SecurityException(string message, Exception inner) : base(message, inner) { }
    }
}