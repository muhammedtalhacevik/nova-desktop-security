namespace Nova.Core.Services.Scanning;

public sealed class PauseTokenSource
{
    private volatile TaskCompletionSource? _paused;

    public bool IsPaused => _paused is not null;
    public PauseToken Token => new(this);

    public void Pause()
    {
        Interlocked.CompareExchange(ref _paused, new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously), null);
    }

    public void Resume()
    {
        var tcs = Interlocked.Exchange(ref _paused, null);
        tcs?.TrySetResult();
    }

    internal Task WaitWhilePausedAsync(CancellationToken ct) => _paused?.Task.WaitAsync(ct) ?? Task.CompletedTask;
}

public readonly struct PauseToken(PauseTokenSource? source)
{
    public Task WaitWhilePausedAsync(CancellationToken ct) => source?.WaitWhilePausedAsync(ct) ?? Task.CompletedTask;
}
