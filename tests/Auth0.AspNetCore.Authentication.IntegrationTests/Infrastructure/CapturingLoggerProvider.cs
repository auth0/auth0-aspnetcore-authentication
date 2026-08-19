using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using Microsoft.Extensions.Logging;

namespace Auth0.AspNetCore.Authentication.IntegrationTests.Infrastructure
{
    /// <summary>
    /// An <see cref="ILoggerProvider"/> that records every logged message, for asserting on warnings.
    /// </summary>
    public sealed class CapturingLoggerProvider : ILoggerProvider
    {
        public ConcurrentQueue<CapturedLog> Logs { get; } = new ConcurrentQueue<CapturedLog>();

        public ILogger CreateLogger(string categoryName) => new CapturingLogger(categoryName, Logs);

        public void Dispose() { }

        public sealed record CapturedLog(string Category, LogLevel Level, string Message);

        private sealed class CapturingLogger : ILogger
        {
            private readonly string _category;
            private readonly ConcurrentQueue<CapturedLog> _logs;

            public CapturingLogger(string category, ConcurrentQueue<CapturedLog> logs)
            {
                _category = category;
                _logs = logs;
            }

            public IDisposable BeginScope<TState>(TState state) => NullScope.Instance;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, System.Exception exception,
                System.Func<TState, System.Exception, string> formatter)
            {
                _logs.Enqueue(new CapturedLog(_category, logLevel, formatter(state, exception)));
            }

            private sealed class NullScope : IDisposable
            {
                public static readonly NullScope Instance = new NullScope();
                public void Dispose() { }
            }
        }
    }
}
