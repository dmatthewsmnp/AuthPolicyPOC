namespace AuthPolicyPOC.Exceptions;

public class RequestParsingException : ApplicationException
{
    /// <inheritdoc />
    public RequestParsingException(string message, params object?[] arguments) : base(
        arguments.Length > 0 ? string.Format(message, arguments) : message)
    { }
}
