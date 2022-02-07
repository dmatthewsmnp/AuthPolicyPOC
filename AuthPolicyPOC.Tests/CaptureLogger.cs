using System;
using System.Collections.Generic;
using System.Text;
using Microsoft.Extensions.Logging;

namespace AuthPolicyPOC.Tests;

/// <summary>
/// ILogger implementation capturing logging results into local collection
/// </summary>
public class CaptureLogger : ILogger
{
	#region Fields and constructor
	private readonly string _categoryName;
	private readonly LoggerExternalScopeProvider _scopeProvider = new();
	private readonly List<string> _capturedLines = new();
	public CaptureLogger(string? categoryName = null) => _categoryName = categoryName ?? string.Empty;
	#endregion

	#region Public factory functions
	public static CaptureLogger CreateLogger() => new();
	public static CaptureLogger<T> CreateLogger<T>() => new();
	#endregion

	#region Public captured log accessors
	/// <summary>
	/// Access captured lines (as read-only collection)
	/// </summary>
	public IReadOnlyList<string> CapturedLines { get => _capturedLines; }

	/// <summary>
	/// Clear all captured logging data
	/// </summary>
	public void ClearCapturedLines()
	{
		_capturedLines.Clear();
	}
	#endregion

	#region ILogger implementation
	public bool IsEnabled(LogLevel logLevel) => logLevel != LogLevel.None;

	public IDisposable BeginScope<TState>(TState state) => _scopeProvider.Push(state);

	public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
	{
		var sb = new StringBuilder()
			.Append(GetLogLevelString(logLevel))
			.Append(" [").Append(_categoryName).Append("] ")
			.Append(formatter(state, exception));

		if (exception != null)
		{
			sb.Append('\n').Append(exception);
		}

		_capturedLines.Add(sb.ToString());
	}
	#endregion

	#region Private methods
	private static string GetLogLevelString(LogLevel logLevel)
	{
		return logLevel switch
		{
			LogLevel.Trace => "trce",
			LogLevel.Debug => "dbug",
			LogLevel.Information => "info",
			LogLevel.Warning => "warn",
			LogLevel.Error => "fail",
			LogLevel.Critical => "crit",
			_ => throw new ArgumentOutOfRangeException(nameof(logLevel))
		};
	}
	#endregion
}

/// <summary>
/// Typed version of CaptureLogger (providing type as category name of base class)
/// </summary>
public sealed class CaptureLogger<T> : CaptureLogger, ILogger<T>
{
	internal CaptureLogger() : base(typeof(T).FullName)
	{
	}
}